------------------------------ MODULE Replace ------------------------------
(***************************************************************************)
(* A compact, a change of passphrase and a create write a new archive to  *)
(* a temporary file beside the path, make it durable, and rename it over  *)
(* the path (doc/design.md 9.3, 9.7). Then they make the directory        *)
(* durable. The power can fail at any moment.                             *)
(*                                                                         *)
(* The disk is that of Commit.tla, for the new file and for the           *)
(* directory. A rename is atomic: after a power failure, the path names   *)
(* the old file or the new one. The old file is durable, and nothing      *)
(* writes to it.                                                           *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    SyncBeforeRename,   \* fsync of the new file, before the rename
    SyncDir             \* fsync of the directory, before success (none on Windows)

R == {"body", "index", "trailer"}

VARIABLES
    file,       \* the new file: region -> "absent", "ok" or "torn" on the disk
    fileCache,  \* the writes to the new file since its last fsync
    named,      \* the file that the path names on the disk: "old" or "new"
    dirCache,   \* the renames since the last fsync of the directory
    pc,
    result

vars == <<file, fileCache, named, dirCache, pc, result>>

Apply(d, r) == [d EXCEPT ![r] = "ok"]
Torn(d, r) == [d EXCEPT ![r] = "torn"]

RECURSIVE After(_, _)
After(ds, ops) ==
    IF ops = <<>> THEN ds
    ELSE After(ds \cup {Apply(d, Head(ops)) : d \in ds}
                  \cup {Torn(d, Head(ops)) : d \in ds}, Tail(ops))
RECURSIVE All(_, _)
All(d, ops) == IF ops = <<>> THEN d ELSE All(Apply(d, Head(ops)), Tail(ops))

\* After a power failure: the file that the path names, and the content of
\* the new file.
CrashNames == IF dirCache = <<>> THEN {named} ELSE {named, "new"}
CrashFiles == After({file}, fileCache)

\* What a reader makes of the path. A new file with a region that is not on
\* the disk is refused, and --repair cannot give the old archive back: the
\* rename removed it.
Recover(n, f) ==
    IF n = "old" THEN "old"
    ELSE IF \A r \in R : f[r] = "ok" THEN "new" ELSE "lost"

Init ==
    /\ file = [r \in R |-> "absent"]
    /\ fileCache = <<>>
    /\ named = "old"
    /\ dirCache = <<>>
    /\ pc = "body"
    /\ result = "none"

Step(from, to, action) == pc = from /\ action /\ pc' = to

W(from, to, r) == Step(from, to, fileCache' = Append(fileCache, r)
                        /\ UNCHANGED <<file, named, dirCache, result>>)
Body == W("body", "index", "body")
Index == W("index", "trailer", "index")
Trailer == W("trailer", IF SyncBeforeRename THEN "sync" ELSE "rename", "trailer")
Sync == Step("sync", "rename", file' = All(file, fileCache) /\ fileCache' = <<>>
                                /\ UNCHANGED <<named, dirCache, result>>)
Rename == Step("rename", IF SyncDir THEN "syncdir" ELSE "success",
               dirCache' = Append(dirCache, "rename")
               /\ UNCHANGED <<file, fileCache, named, result>>)
SyncDirectory == Step("syncdir", "success",
               named' = (IF dirCache = <<>> THEN named ELSE "new") /\ dirCache' = <<>>
               /\ UNCHANGED <<file, fileCache, result>>)
Success == Step("success", "done", result' = "success"
                /\ UNCHANGED <<file, fileCache, named, dirCache>>)

\* An error before the rename removes the temporary file, and leaves the
\* path. An error of the fsync of the directory comes after the commit.
Fail == /\ pc \in {"body", "index", "trailer", "sync", "rename"}
        /\ pc' = "done" /\ result' = "error"
        /\ UNCHANGED <<file, fileCache, named, dirCache>>
SyncDirFails == Step("syncdir", "done", result' = "error"
                /\ UNCHANGED <<file, fileCache, named, dirCache>>)

Next == Body \/ Index \/ Trailer \/ Sync \/ Rename \/ SyncDirectory \/ Success
        \/ Fail \/ SyncDirFails \/ (pc = "done" /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ file \in [R -> {"absent", "ok", "torn"}]
    /\ named \in {"old", "new"}
    /\ result \in {"none", "success", "error"}

\* After a power failure in each state: the path gives the old archive or
\* the complete new one.
OldOrNew == \A n \in CrashNames, f \in CrashFiles : Recover(n, f) \in {"old", "new"}

\* A success is durable.
SuccessIsDurable ==
    result = "success" => \A n \in CrashNames, f \in CrashFiles : Recover(n, f) = "new"
=============================================================================
