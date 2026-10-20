#!/usr/bin/env bash
# Build and test eictar against the local fork of klauspost/compress.
#
#   ./build-fork.sh [FUZZTIME]     default 10m; "none" skips the fuzz step
#
# The fork comes from fork.work (GOWORK). The steps stop at the first
# failure: make check, make fuzz (12 targets, FUZZTIME each), make build.
# The binary is .build/eictar-fork. .build/eictar stays the build from the
# release in go.mod, so the two do not mix.
#
# To limit the CPUs: nice -n 19 taskset -c 0-14 ./build-fork.sh
set -euo pipefail

cd "$(dirname "$0")"
FUZZTIME=${1:-10m}
[ -f fork.work ] || { echo "build-fork: no fork.work in $PWD" >&2; exit 2; }
export GOWORK=$PWD/fork.work
# The caches of the Makefile, for the go commands here.
export GOMODCACHE=$PWD/.gocache GOCACHE=$PWD/.gobuildcache TMPDIR=$PWD/.tmp

step() { echo; echo "=== $1 ($(date '+%H:%M'))"; }

step "the compress that eictar uses"
/opt/go/bin/go list -m -f '{{.Path}} {{if .Dir}}{{.Dir}}{{end}}' github.com/klauspost/compress

step "make check"
make --no-print-directory check

if [ "$FUZZTIME" != none ]; then
	step "make fuzz FUZZTIME=$FUZZTIME"
	make --no-print-directory fuzz FUZZTIME="$FUZZTIME"
fi

step "make build"
make --no-print-directory build BIN=.build/eictar-fork
/opt/go/bin/go version -m .build/eictar-fork | grep 'klauspost/compress'
echo
echo "build-fork: done. The binary is .build/eictar-fork"
