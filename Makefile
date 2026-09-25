# eictar
#
# The toolchain lives at /opt/go and the module cache is kept inside the
# project, so a build touches nothing outside this directory.

# The toolchain. CI and other machines give their own: make check GO=go
GO          ?= /opt/go/bin/go
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

.PHONY: all build test test-race operational fuzz bench compare vet fmt check check-norace clean

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

vet: | $(TMPDIR)
	$(GO) vet $(PKGS)
	$(GO) vet -tags operational ./src/operational/

fmt: | $(TMPDIR)
	$(GO) fmt $(PKGS)

check: fmt vet test-race operational

# check without the race detector, for platforms that do not have it
# (NetBSD, OpenBSD).
check-norace: fmt vet test operational

clean:
	rm -rf .build .tmp
