# eictar
#
# The toolchain lives at /opt/go and the module cache is kept inside the
# project, so a build touches nothing outside this directory.

# The toolchain. CI and other machines give their own: make check GO=go
GO          ?= /opt/go/bin/go
# An empty GO would run whatever the first word of the recipe names: for
# "$(GO) fmt", the text formatter fmt(1).
ifeq ($(strip $(GO)),)
$(error GO is empty; give the go command, for example GO=go)
endif
export GOMODCACHE := $(CURDIR)/.gocache
# The build cache, which also holds the fuzz corpus. Go's default is
# ~/.cache/go-build, outside the project. CI gives the directories that
# setup-go saves between runs, on the command line: make check GOCACHE=...
export GOCACHE    := $(CURDIR)/.gobuildcache
export GOTOOL     := $(GO)
# Temporary files - t.TempDir(), the test binary build, spill files from
# library callers - stay inside the project too (see CLAUDE.md).
export TMPDIR     := $(CURDIR)/.tmp

BIN      := .build/eictar
PKGS     := ./src/...
FUZZTIME ?= 30s

# The version that --version prints. A local build takes it from git
# describe: 1.0.1 at a tag, 1.0.1-2-g5ccd0ce two commits after it, with
# -dirty for uncommitted changes. Outside a git checkout it is dev. Override
# it for a release:
#   make build VERSION=1.0.0
# The release workflow (.github/workflows/release.yml) sets it from the tag.
VERSION  ?= $(or $(shell git describe --tags --dirty 2>/dev/null | sed 's/^v//'),dev)

# -trimpath keeps local paths out of the binary, which also makes the build
# reproducible. -s -w drop the symbol table and the DWARF debug information:
# the same result as strip(1). Panic stack traces keep their function names
# and lines. A debugger (Delve) needs a build without -s -w.
LDFLAGS    := -s -w -X github.com/philmalin/eictar/src/internal/cli.Version=$(VERSION)
BUILDFLAGS := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build release test test-race operational large cover mutate fuzz bench compare stress stress-build vet crossvet fmt check check-norace skips clean

all: build

$(TMPDIR):
	@mkdir -p $(TMPDIR)

build: | $(TMPDIR)
	$(GO) build $(BUILDFLAGS) -o $(BIN) ./src/cmd/eictar

# The release binaries: one directory for each platform that the CI workflow
# tests (doc/design.md 15.1), with the man page, the README and the license.
# Windows gets eictar.exe, and no man page.
# The release workflow packs each directory and writes the checksums.
#   make release VERSION=1.0.0
RELEASE_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
                   freebsd/amd64 freebsd/arm64 netbsd/amd64 netbsd/arm64 \
                   openbsd/amd64 openbsd/arm64 windows/amd64 windows/arm64
release: | $(TMPDIR)
	rm -rf .build/release
	@for t in $(RELEASE_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; dir=.build/release/eictar-$(VERSION)-$$os-$$arch; \
		exe=eictar; man=doc/eictar.1; \
		if [ $$os = windows ]; then exe=eictar.exe; man=; fi; \
		echo "$$os/$$arch"; \
		mkdir -p $$dir && \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -o $$dir/$$exe ./src/cmd/eictar && \
		cp $$man README.md LICENSE TRADEMARKS.md THIRD_PARTY.md $$dir/ || exit 1; \
	done

test: | $(TMPDIR)
	$(GO) test $(PKGS) ./tools/...

test-race: | $(TMPDIR)
	$(GO) test -race $(PKGS) ./tools/...

# Drives the compiled binary end to end; see doc/design.md 13.2.
operational: | $(TMPDIR)
	$(GO) test -tags operational ./src/operational/

# An archive larger than 4 GiB through each operation (doc/design.md 13.2).
# LARGE is the size of its large file in GiB. The test needs approximately
# four times that much free space in .tmp/.
LARGE ?= 4
large: | $(TMPDIR)
	EICTAR_TEST_LARGE=$(LARGE) $(GO) test -count=1 -tags operational -run TestLargeArchive -timeout 2h -v ./src/operational/

# The coverage of the unit tests and the operational tests together
# (doc/design.md 13.5). The operational tests run a binary that is built with
# coverage, and each run writes its counts into GOCOVERDIR. The report is in
# .tmp/cover: cover.txt for each function, and cover.html.
COVERDIR := $(CURDIR)/.tmp/cover
COVERPKG  = $(shell $(GO) list ./src/... | grep -v /testutil | paste -sd, -)

cover: | $(TMPDIR)
	rm -rf $(COVERDIR)
	mkdir -p $(COVERDIR)/unit $(COVERDIR)/operational
	$(GO) test -count=1 -cover -coverpkg=$(COVERPKG) $(PKGS) -args -test.gocoverdir=$(COVERDIR)/unit
	GOCOVERDIR=$(COVERDIR)/operational $(GO) test -count=1 -tags operational ./src/operational/
	$(GO) tool covdata textfmt -i=$(COVERDIR)/unit,$(COVERDIR)/operational -pkg=$(COVERPKG) -o $(COVERDIR)/cover.out
	$(GO) tool cover -func=$(COVERDIR)/cover.out > $(COVERDIR)/cover.txt
	$(GO) tool cover -html=$(COVERDIR)/cover.out -o $(COVERDIR)/cover.html
	@echo "=== unit tests alone"
	@$(GO) tool covdata percent -i=$(COVERDIR)/unit -pkg=$(COVERPKG)
	@echo "=== unit and operational tests"
	@$(GO) tool covdata percent -i=$(COVERDIR)/unit,$(COVERDIR)/operational -pkg=$(COVERPKG)
	@tail -1 $(COVERDIR)/cover.txt

# Mutation testing (doc/design.md 13.5): one small change at a time to the
# code of each package in MUTATE, and its tests. A change that no test finds
# is a survivor. MUTATE_FLAGS passes options, for example:
#   make mutate MUTATE=./src/internal/archive MUTATE_FLAGS="-files '^dict' -j 8"
# go run ./tools/mutate -h lists the options.
MUTATE       ?= ./src/internal/format ./src/internal/crypt ./src/internal/pipeline
MUTATE_FLAGS ?=

mutate: | $(TMPDIR)
	$(GO) run ./tools/mutate $(MUTATE_FLAGS) $(MUTATE)

fuzz: | $(TMPDIR)
	@for t in FuzzHeaderUnmarshal FuzzTrailerUnmarshal FuzzDecodeIndex FuzzUnmarshalCryptoHeader; do \
		echo "=== $$t"; \
		$(GO) test ./src/internal/format/ -run=XXX -fuzz=$$t -fuzztime=$(FUZZTIME) || exit 1; \
	done
	@for t in FuzzDecoders FuzzZstdDictionary; do \
		echo "=== $$t"; \
		$(GO) test ./src/internal/codec/ -run=XXX -fuzz=$$t -fuzztime=$(FUZZTIME) || exit 1; \
	done

# Go benchmarks of eictar alone: create and extract throughput per codec.
bench: | $(TMPDIR)
	$(GO) test ./src/internal/archive/ -run=XXX -bench=. -benchtime=3x

# eictar against tar piped into zstd, xz and gzip, on DIR (default: the module
# cache). Needs tar, zstd, xz and gzip on PATH. See bench/compare.sh.
compare: build
	bench/compare.sh $(DIR)

# List the tests that this platform skips, with their reasons. CI runs it
# after check, so that a green job also says what it did not test.
skips: | $(TMPDIR)
	@echo "=== unit tests"
	@$(GO) test -count=1 -json ./src/... | $(GO) run ./tools/testskips
	@echo "=== operational tests"
	@$(GO) test -count=1 -json -tags operational ./src/operational/ | $(GO) run ./tools/testskips

# Random end-to-end testing against a model of the archive (doc/design.md
# 13.4). STRESS passes options, for example:
#   make stress STRESS="-duration 30m"
#   make stress STRESS="-seed 1234 -sequences 1"
# make stress-build builds the tester alone, to run it as .build/stress
# (.build/stress -h lists its options).
STRESS_BIN := .build/stress

stress: build stress-build
	$(STRESS_BIN) -eictar $(BIN) $(STRESS)

stress-build: | $(TMPDIR)
	$(GO) build -trimpath -o $(STRESS_BIN) ./tools/stress

vet: | $(TMPDIR)
	$(GO) vet $(PKGS) ./tools/...
	$(GO) vet -tags operational ./src/operational/

# vet for each platform of CI (doc/design.md 15.1), from this machine. A
# file for one platform can use a name that another platform does not have,
# and only a build for that platform shows it.
CROSS_GOOS := linux darwin freebsd netbsd openbsd windows

crossvet: | $(TMPDIR)
	@set -e; for os in $(CROSS_GOOS); do \
		echo "vet GOOS=$$os"; \
		GOOS=$$os $(GO) vet $(PKGS) ./tools/...; \
		GOOS=$$os $(GO) vet -tags operational ./src/operational/; \
	done

fmt: | $(TMPDIR)
	$(GO) fmt $(PKGS) ./tools/...

# CI builds and tests on each platform itself, so it leaves crossvet out:
# make check CROSSVET=
CROSSVET ?= crossvet

check: fmt vet $(CROSSVET) test-race operational

# check without the race detector, for platforms that do not have it
# (NetBSD, OpenBSD).
check-norace: fmt vet $(CROSSVET) test operational

clean:
	rm -rf .build .tmp
