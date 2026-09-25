#!/usr/bin/env bash
# Compare eictar with tar piped into a compressor, on one directory.
#
#   bench/compare.sh [DIR]        default: .gocache (the module cache)
#
# For each pair it reports the archive size, the create time and the extract
# time. It needs tar, zstd, xz and gzip on PATH, and a built .build/eictar
# (make build). Scratch files go to .tmp/bench, inside the project.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=${1:-.gocache}
EICTAR=$PWD/.build/eictar
WORK=$PWD/.tmp/bench
[ -x "$EICTAR" ] || { echo "build eictar first: make build" >&2; exit 1; }

cleanup() { chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
cleanup
mkdir -p "$WORK"

PARENT=$(cd "$(dirname "$SRC")" && pwd)
BASE=$(basename "$SRC")
INPUT=$(du -sb "$SRC" | cut -f1)
FILES=$(find "$SRC" -type f | wc -l)
printf 'input: %s, %d bytes in %d files, %d CPUs\n\n' "$SRC" "$INPUT" "$FILES" "$(nproc)"
printf '%-34s %12s %7s %9s %9s\n' "method" "bytes" "ratio" "create" "extract"

now() { date +%s.%N; }

# row NAME ARCHIVE CREATE-CMD EXTRACT-CMD
row() {
	local name=$1 archive=$2 create=$3 extract=$4 t0 t1 t2 size
	rm -rf "$WORK/out" "$archive"; mkdir -p "$WORK/out"
	t0=$(now); bash -c "$create"; t1=$(now)
	bash -c "$extract"; t2=$(now)
	size=$(stat -c %s "$archive")
	printf '%-34s %12d %6.1f%% %8.2fs %8.2fs\n' "$name" "$size" \
		"$(echo "100*$size/$INPUT" | bc -l)" "$(echo "$t1-$t0" | bc)" "$(echo "$t2-$t1" | bc)"
	chmod -R u+w "$WORK/out"
}

T="tar -C '$PARENT' -cf - '$BASE'"
X="tar -C '$WORK/out' -xf -"
E="'$EICTAR' -cf"
EX="'$EICTAR' -xf"
PASS=$WORK/pass; echo "benchmark passphrase" > "$PASS"

row "tar | zstd -3 -T0"          "$WORK/a.tar.zst" "$T | zstd -q -3 -T0 -o '$WORK/a.tar.zst'"  "zstd -q -dc '$WORK/a.tar.zst' | $X"
row "eictar zstd:level=3"        "$WORK/a.e"       "$E '$WORK/a.e' -C '$PARENT' '$BASE'"         "$EX '$WORK/a.e' -d '$WORK/out'"
row "tar | zstd -19 -T0"         "$WORK/b.tar.zst" "$T | zstd -q -19 -T0 -o '$WORK/b.tar.zst'" "zstd -q -dc '$WORK/b.tar.zst' | $X"
row "eictar zstd:level=19"       "$WORK/b.e"       "$E '$WORK/b.e' -C '$PARENT' -Z zstd:level=19 '$BASE'" "$EX '$WORK/b.e' -d '$WORK/out'"
row "tar | xz -6 -T0"            "$WORK/c.tar.xz"  "$T | xz -q -6 -T0 > '$WORK/c.tar.xz'"      "xz -q -dc '$WORK/c.tar.xz' | $X"
row "eictar xz:preset=6"         "$WORK/c.e"       "$E '$WORK/c.e' -C '$PARENT' -J '$BASE'"      "$EX '$WORK/c.e' -d '$WORK/out'"
row "tar | gzip -6"              "$WORK/d.tar.gz"  "$T | gzip -6 > '$WORK/d.tar.gz'"            "gzip -dc '$WORK/d.tar.gz' | $X"
row "eictar gzip:level=6"        "$WORK/d.e"       "$E '$WORK/d.e' -C '$PARENT' -z '$BASE'"      "$EX '$WORK/d.e' -d '$WORK/out'"
row "eictar s2"                  "$WORK/e.e"       "$E '$WORK/e.e' -C '$PARENT' -Z s2 '$BASE'"   "$EX '$WORK/e.e' -d '$WORK/out'"
row "eictar zstd:level=3 -e"     "$WORK/f.e"       "$E '$WORK/f.e' -C '$PARENT' -e --passphrase-file '$PASS' '$BASE'" \
	"$EX '$WORK/f.e' -d '$WORK/out' --passphrase-file '$PASS'"
