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
# ~/.cache/go-build, outside the project.
export GOCACHE    := $(CURDIR)/.gobuildcache
export GOTOOL     := $(GO)
# Temporary files - t.TempDir(), the test binary build, spill files from
# library callers - stay inside the project too (see CLAUDE.md).
export TMPDIR     := $(CURDIR)/.tmp

BIN      := .build/eictar
PKGS     := ./src/...
FUZZTIME ?= 30s

# The version that --version prints. Override it for a release:
#   make build VERSION=1.0.0
VERSION  ?= dev

# -trimpath keeps local paths out of the binary, which also makes the build
# reproducible. -s -w drop the symbol table and the DWARF debug information:
# the same result as strip(1). Panic stack traces keep their function names
# and lines. A debugger (Delve) needs a build without -s -w.
LDFLAGS    := -s -w -X eictar/src/internal/cli.Version=$(VERSION)
BUILDFLAGS := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build test test-race operational fuzz bench compare vet fmt check check-norace skips clean

all: build

$(TMPDIR):
	@mkdir -p $(TMPDIR)

build: | $(TMPDIR)
	$(GO) build $(BUILDFLAGS) -o $(BIN) ./src/cmd/eictar

test: | $(TMPDIR)
	$(GO) test $(PKGS)

test-race: | $(TMPDIR)
	$(GO) test -race $(PKGS)

# Drives the compiled binary end to end; see doc/design.md 13.2.
operational: | $(TMPDIR)
	$(GO) test -tags operational ./src/operational/

fuzz: | $(TMPDIR)
	@for t in FuzzHeaderUnmarshal FuzzTrailerUnmarshal FuzzDecodeIndex FuzzUnmarshalCryptoHeader; do \
		echo "=== $$t"; \
		$(GO) test ./src/internal/format/ -run=XXX -fuzz=$$t -fuzztime=$(FUZZTIME) || exit 1; \
	done
	@echo "=== FuzzDecoders"
	$(GO) test ./src/internal/codec/ -run=XXX -fuzz=FuzzDecoders -fuzztime=$(FUZZTIME)

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

vet: | $(TMPDIR)
	$(GO) vet $(PKGS) ./tools/...
	$(GO) vet -tags operational ./src/operational/

fmt: | $(TMPDIR)
	$(GO) fmt $(PKGS) ./tools/...

check: fmt vet test-race operational

# check without the race detector, for platforms that do not have it
# (NetBSD, OpenBSD).
check-norace: fmt vet test operational

clean:
	rm -rf .build .tmp
