------------------------------ MODULE Commit ------------------------------
(***************************************************************************)
(* An append, an update or a delete writes a new generation in place      *)
(* (doc/design.md 9.1). The writer puts the blobs and the index after the *)
(* old end of the file, makes them durable, writes the trailer, and makes *)
(* it durable. An error before the end cuts the file back to its old      *)
(* length. The power can fail at any moment.                              *)
(*                                                                         *)
(* The disk: each write and each truncate goes to a cache first. An fsync *)
(* puts the cache on the disk. When the power fails, any subset of the    *)
(* cached operations can be on the disk, in the order of the program, and *)
(* a write can be torn. Thus writes reach the disk out of order. The old  *)
(* part of the file is durable, and no write touches it.                  *)
(*                                                                         *)
(* After the failure, a reader opens the file, or refuses it, and then    *)
(* --repair cuts it after the last valid trailer (doc/design.md 9.5).     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    SyncBeforeTrailer,   \* fsync of the blobs and the index, before the trailer
    SyncAfterTrailer,    \* fsync of the trailer, before success
    SyncAfterTruncate    \* fsync of the truncate that undoes a failed append

\* The new regions, in the order of the file, after the old end.
Regions == <<"blobs", "index", "trailer">>
R == {"blobs", "index", "trailer"}

VARIABLES
    disk,      \* region -> "absent", "ok" or "torn": what is on the disk
    cache,     \* the operations since the last fsync, in order
    pc,        \* the step of the writer
    result,    \* "none", "success" or "error"
    cutOK      \* FALSE when the truncate of a failed append failed

vars == <<disk, cache, pc, result, cutOK>>

Write(r) == [kind |-> "write", region |-> r]
Cut == [kind |-> "truncate", region |-> "none"]

\* The disk after one operation, whole or torn.
Apply(d, op) ==
    IF op.kind = "write" THEN [d EXCEPT ![op.region] = "ok"]
    ELSE [r \in R |-> "absent"]
Torn(d, op) ==
    IF op.kind = "write" THEN [d EXCEPT ![op.region] = "torn"] ELSE d

\* The states that the disk can be in after a power failure: each cached
\* operation in turn is on the disk, torn, or not.
RECURSIVE After(_, _)
After(ds, ops) ==
    IF ops = <<>> THEN ds
    ELSE After(ds \cup {Apply(d, Head(ops)) : d \in ds}
                  \cup {Torn(d, Head(ops)) : d \in ds}, Tail(ops))
CrashDisks == After({disk}, cache)

\* What a reader, and then --repair, makes of a disk. The reader reads the
\* last 96 bytes of the file. A region that is absent, before one that is on
\* the disk, reads as zeros.
Last(d) == IF d["trailer"] # "absent" THEN 3
           ELSE IF d["index"] # "absent" THEN 2
           ELSE IF d["blobs"] # "absent" THEN 1 ELSE 0
Recover(d) ==
    IF Last(d) = 0 THEN "old"
    ELSE IF Last(d) = 3 /\ d["trailer"] = "ok" /\ d["index"] = "ok"
         THEN IF d["blobs"] = "ok" THEN "new"
              \* The trailer and the index pass their checks, and they
              \* describe blobs that are not on the disk.
              ELSE "new with lost blobs"
    \* The reader refuses the file, and --repair finds the old trailer: the
    \* index digest refuses the new one.
    ELSE "old after repair"

Init ==
    /\ disk = [r \in R |-> "absent"]
    /\ cache = <<>>
    /\ pc = "blobs"
    /\ result = "none"
    /\ cutOK = TRUE

RECURSIVE After1(_, _)
After1(d, ops) == IF ops = <<>> THEN d ELSE After1(Apply(d, Head(ops)), Tail(ops))
Fsync == /\ disk' = After1(disk, cache)
         /\ cache' = <<>>

Step(from, to, action) == pc = from /\ action /\ pc' = to

Blobs == Step("blobs", "index",
            cache' = Append(cache, Write("blobs")) /\ UNCHANGED <<disk, result, cutOK>>)
Index == Step("index", IF SyncBeforeTrailer THEN "sync1" ELSE "trailer",
            cache' = Append(cache, Write("index")) /\ UNCHANGED <<disk, result, cutOK>>)
Sync1 == Step("sync1", "trailer", Fsync /\ UNCHANGED <<result, cutOK>>)
Trailer == Step("trailer", IF SyncAfterTrailer THEN "sync2" ELSE "success",
            cache' = Append(cache, Write("trailer")) /\ UNCHANGED <<disk, result, cutOK>>)
Sync2 == Step("sync2", "success", Fsync /\ UNCHANGED <<result, cutOK>>)
Success == Step("success", "done",
            result' = "success" /\ UNCHANGED <<disk, cache, cutOK>>)

\* An error at any step before success: a write, or an fsync, fails. The
\* writer cuts the file back, and makes the cut durable. The truncate can
\* fail too; the writer then gives the first error all the same.
Fail == /\ pc \in {"blobs", "index", "sync1", "trailer", "sync2"}
        /\ pc' = "cut"
        /\ UNCHANGED <<disk, cache, result, cutOK>>
CutBack == Step("cut", IF SyncAfterTruncate THEN "sync3" ELSE "error",
            cache' = Append(cache, Cut) /\ UNCHANGED <<disk, result, cutOK>>)
CutFails == Step("cut", "error", cutOK' = FALSE /\ UNCHANGED <<disk, cache, result>>)
Sync3 == Step("sync3", "error", Fsync /\ UNCHANGED <<result, cutOK>>)
\* The fsync of the cut fails: the cut can be lost.
Sync3Fails == Step("sync3", "error", cutOK' = FALSE /\ UNCHANGED <<disk, cache, result>>)
Error == Step("error", "done", result' = "error" /\ UNCHANGED <<disk, cache, cutOK>>)

Next == Blobs \/ Index \/ Sync1 \/ Trailer \/ Sync2 \/ Success
        \/ Fail \/ CutBack \/ CutFails \/ Sync3 \/ Sync3Fails \/ Error
        \/ (pc = "done" /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ disk \in [R -> {"absent", "ok", "torn"}]
    /\ result \in {"none", "success", "error"}

(***************************************************************************)
(* The properties hold after a power failure in each state.               *)
(***************************************************************************)

\* The archive gives the old generation or the new one, at worst after
\* --repair. Never a generation whose data is not on the disk.
OldOrNew == \A d \in CrashDisks : Recover(d) \in {"old", "new", "old after repair"}

\* A success is durable: the new generation opens, with no repair.
SuccessIsDurable == result = "success" => \A d \in CrashDisks : Recover(d) = "new"

\* A failed append leaves the old archive, with no repair, when the
\* truncate worked (doc/design.md 13.5, step 3).
ErrorLeavesTheOld ==
    (result = "error" /\ cutOK) => \A d \in CrashDisks : Recover(d) = "old"
=============================================================================
