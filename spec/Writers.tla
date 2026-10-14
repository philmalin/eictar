------------------------------ MODULE Writers ------------------------------
(***************************************************************************)
(* Runs that change one archive at the same time (doc/design.md 9.6).     *)
(* Each writer opens the path, which gives it a file (an inode), and takes *)
(* the lock of that file without waiting. A lock is on a file, not on a   *)
(* path. An append writes into its file. A compact writes a new file from *)
(* the content of its file, and renames it over the path. A create locks  *)
(* the file at the path, if there is one, and renames a new file over it. *)
(* After it takes a lock, a writer makes sure that the path still names   *)
(* the file that it locked.                                                *)
(*                                                                         *)
(* The property: an append that reports success is in the archive at the  *)
(* path, unless a create replaced the archive after it.                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Appends, Compacts, Creates,   \* the writers, by kind
    CreateNoReplace,   \* a create that found no archive does not rename over one
    CheckPath,         \* after the lock, the path must still name the file
    LockBeforeRead     \* a compact reads its file after the lock, not before

Procs == Appends \cup Compacts \cup Creates
None == 0
\* File 1 is the archive at the start. Each compact and create makes one.
Files == 1 .. (1 + Cardinality(Compacts \cup Creates))

VARIABLES
    path,       \* the file that the path names, or None
    content,    \* file -> the appends that it holds
    lock,       \* file -> the writer that holds its lock, or None
    nextFile,   \* the next new file
    pc,         \* writer -> its step
    fd,         \* writer -> the file that it opened, or None
    snap,       \* compact -> the content that it read
    succeeded,  \* the appends that reported success
    replaced    \* the appends in an archive that a create replaced

vars == <<path, content, lock, nextFile, pc, fd, snap, succeeded, replaced>>

Init ==
    /\ path \in {1, None}   \* an archive at the path at the start, or none
    /\ content = [f \in Files |-> {}]
    /\ lock = [f \in Files |-> None]
    /\ nextFile = 2
    /\ pc = [p \in Procs |-> "open"]
    /\ fd = [p \in Procs |-> None]
    /\ snap = [p \in Procs |-> {}]
    /\ succeeded = {}
    /\ replaced = {}

Go(p, to) == pc' = [pc EXCEPT ![p] = to]
Unlock(p) == IF fd[p] # None /\ lock[fd[p]] = p
             THEN lock' = [lock EXCEPT ![fd[p]] = None] ELSE UNCHANGED lock

\* Open the path. An append and a compact need a file there. A create
\* locks the file that it replaces, if there is one.
Open(p) ==
    /\ pc[p] = "open"
    /\ fd' = [fd EXCEPT ![p] = path]
    /\ IF path = None
       THEN Go(p, IF p \in Creates THEN "write" ELSE "failed")
       ELSE Go(p, IF p \in Compacts /\ ~LockBeforeRead THEN "read" ELSE "lock")
    /\ UNCHANGED <<path, content, lock, nextFile, snap, succeeded, replaced>>

\* Take the lock without waiting: if another writer holds it, stop.
Lock(p) ==
    /\ pc[p] = "lock"
    /\ IF lock[fd[p]] = None
       THEN /\ lock' = [lock EXCEPT ![fd[p]] = p]
            /\ Go(p, "check")
       ELSE /\ Go(p, "failed") /\ UNCHANGED lock
    /\ UNCHANGED <<path, content, nextFile, fd, snap, succeeded, replaced>>

\* The path must still name the file that the writer locked.
Check(p) ==
    /\ pc[p] = "check"
    /\ IF CheckPath /\ path # fd[p]
       THEN /\ Unlock(p) /\ Go(p, "failed")
       ELSE /\ UNCHANGED lock
            /\ Go(p, IF p \in Appends \/ p \in Creates THEN "write"
                     ELSE IF LockBeforeRead THEN "read" ELSE "write")
    /\ UNCHANGED <<path, content, nextFile, fd, snap, succeeded, replaced>>

\* A compact reads the trailer and the index of its file.
Read(p) ==
    /\ pc[p] = "read"
    /\ snap' = [snap EXCEPT ![p] = content[fd[p]]]
    /\ Go(p, IF LockBeforeRead THEN "write" ELSE "lock")
    /\ UNCHANGED <<path, content, lock, nextFile, fd, succeeded, replaced>>

\* An append commits its generation into its file, and reports success.
AppendWrite(p) ==
    /\ pc[p] = "write" /\ p \in Appends
    /\ content' = [content EXCEPT ![fd[p]] = @ \cup {p}]
    /\ succeeded' = succeeded \cup {p}
    /\ Unlock(p) /\ Go(p, "done")
    /\ UNCHANGED <<path, nextFile, fd, snap, replaced>>

\* A compact renames a new file, with what it read, over the path. A create
\* renames a new file with no append in it.
\* A create that found no archive at the path, when one is there now: the
\* rename that does not replace a file fails.
RenameRefused(p) ==
    /\ pc[p] = "write" /\ p \in Creates /\ fd[p] = None /\ path # None
    /\ CreateNoReplace
    /\ Go(p, "failed")
    /\ UNCHANGED <<path, content, lock, nextFile, fd, snap, succeeded, replaced>>

RenameWrite(p) ==
    /\ pc[p] = "write" /\ p \in Compacts \cup Creates
    /\ ~(p \in Creates /\ fd[p] = None /\ path # None /\ CreateNoReplace)
    /\ content' = [content EXCEPT ![nextFile] = IF p \in Compacts THEN snap[p] ELSE {}]
    /\ path' = nextFile
    /\ nextFile' = nextFile + 1
    /\ replaced' = IF p \in Creates /\ path # None THEN replaced \cup content[path]
                   ELSE replaced
    /\ Unlock(p) /\ Go(p, "done")
    /\ UNCHANGED <<fd, snap, succeeded>>

Next == \/ \E p \in Procs : Open(p) \/ Lock(p) \/ Check(p) \/ Read(p)
                            \/ AppendWrite(p) \/ RenameWrite(p) \/ RenameRefused(p)
        \/ (\A p \in Procs : pc[p] \in {"done", "failed"}) /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ path \in Files \cup {None}
    /\ content \in [Files -> SUBSET Appends]
    /\ lock \in [Files -> Procs \cup {None}]

\* No append that reported success is lost.
NoLostAppend ==
    \A a \in succeeded : (path # None /\ a \in content[path]) \/ a \in replaced
=============================================================================
