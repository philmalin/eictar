#!/bin/sh
# The release gate (doc/testing.md 5, step 6): make gate runs this.
#
# It checks out the commit GATE_REF in a git worktree under .tmp/gate/, and
# runs each step there, so that the result belongs to that commit and not
# to the changes in the working tree. The worktree uses the caches of the
# project, so the fuzz corpus in GOCACHE grows from one gate to the next.
#
# Each step writes its output to a log in .build/gate/SHA/. The record
# .build/gate/SHA/record.txt gives the commit, the toolchain, and the result
# and time of each step. Its last line is PASS only when every step ran and
# passed. The gate stops at the first step that fails: a fix makes a new
# commit, and the gate must run again on it.
#
# The environment gives the settings (the Makefile sets the defaults):
#   GO GOMODCACHE GOCACHE  the toolchain and the caches of the project
#   GATE_REF               the commit to test
#   GATE_STEPS             the steps, in order
#   GATE_FUZZTIME          the time of each fuzz target
#   GATE_STRESSTIME        the time of the stress tester
#   GATE_MUTATE            the packages for tools/mutate
#   GOVULNCHECK            the module of govulncheck, at its version
#   TLA_JAR JAVA           TLC, for make tla

set -u

root=$(pwd)
sha=$(git rev-parse --verify "$GATE_REF^{commit}") || exit 2
short=$(git rev-parse --short "$sha")
out=$root/.build/gate/$short
wt=$root/.tmp/gate/$short
record=$out/record.txt

case $TLA_JAR in /*) ;; *) TLA_JAR=$root/$TLA_JAR ;; esac

# removewt removes the worktree. Some tests leave a directory that its owner
# cannot read or write, and git worktree remove then fails.
removewt() {
	if [ -d "$wt" ]; then
		chmod -R u+rwx "$wt" && rm -rf "$wt" || return 1
	fi
	git worktree prune
}

rm -rf "$out"
mkdir -p "$out" "$root/.tmp/gate"
removewt || exit 2
git worktree add --detach "$wt" "$sha" >/dev/null || exit 2

{
	echo "commit    $sha ($(git log -1 --format=%s "$sha" | cut -c1-60))"
	echo "toolchain $($GO version)"
	echo "started   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
	echo "steps     $GATE_STEPS"
	echo "fuzz      $GATE_FUZZTIME for each target; stress $GATE_STRESSTIME"
	echo
} >"$record"

# make in the worktree, with the caches of the project.
mk() {
	make -C "$wt" --no-print-directory GO="$GO" GOMODCACHE="$GOMODCACHE" GOCACHE="$GOCACHE" "$@"
}

step_check() { mk check; }
step_tla() { mk tla JAVA="$JAVA" TLA_JAR="$TLA_JAR"; }
step_vuln() { "$GO" run "$GOVULNCHECK" ./src/...; }
step_fuzz() { mk fuzz FUZZTIME="$GATE_FUZZTIME"; }
step_stress() { mk stress STRESS="-duration $GATE_STRESSTIME"; }

# Each package alone, so that the log gives a result for each. The tests of
# cli count with the operational tests, which build the binary with the
# mutant (doc/testing.md 5, step 1). Four threads for each of eight
# mutants keep the machine busy and no more.
step_mutate() {
	for p in $GATE_MUTATE; do
		flags=
		if [ "$p" = cli ]; then
			flags="-tags operational -test ./src/internal/cli,./src/operational"
		fi
		echo "=== $p"
		GOMAXPROCS=4 mk mutate MUTATE=./src/internal/$p MUTATE_FLAGS="-j 8 $flags" || return 1
	done
}

for s in $GATE_STEPS; do
	case $s in
	check | tla | vuln | mutate | fuzz | stress) ;;
	*)
		echo "gate: unknown step $s" >&2
		exit 2
		;;
	esac
	log=$out/$s.log
	echo "=== $s (from $(date '+%H:%M'); log: .build/gate/$short/$s.log)"
	t0=$(date +%s)
	if (cd "$wt" && "step_$s") >"$log" 2>&1; then
		result=ok
	else
		result=FAIL
	fi
	t=$(($(date +%s) - t0))
	line=$(printf '%-6s %-5s %3dh%02dm' "$s" "$result" $((t / 3600)) $((t % 3600 / 60)))
	echo "$line" >>"$record"
	echo "$line"
	if [ $result = FAIL ]; then
		tail -20 "$log"
		{
			echo
			echo "FAIL in $s; the worktree stays in .tmp/gate/$short"
		} >>"$record"
		echo "gate: FAIL in $s. The record: .build/gate/$short/record.txt"
		exit 1
	fi
done

# A fuzz target that finds a fault writes the input to testdata/fuzz in the
# worktree. The step then fails, so here there is none. The worktree goes.
removewt

all=true
for s in check tla vuln mutate fuzz stress; do
	case " $GATE_STEPS " in *" $s "*) ;; *) all=false ;; esac
done
echo >>"$record"
echo "ended     $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >>"$record"
if $all; then
	echo PASS >>"$record"
	echo "gate: PASS for $short. The record: .build/gate/$short/record.txt"
else
	echo "PARTIAL: not every step ran" >>"$record"
	echo "gate: the steps passed, but not every step ran: no PASS for $short"
fi
