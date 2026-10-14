------------------------------ MODULE Budget ------------------------------
(***************************************************************************)
(* The memory budget of a create (doc/design.md 8.1), against a deadlock. *)
(*                                                                         *)
(* One reader reads the members in turn, chunk by chunk. It takes one     *)
(* chunk of budget before each read, and holds back the last chunk that   *)
(* it read until it knows whether another follows. It sends each chunk to *)
(* a queue of Workers places. A worker compresses the chunk, gives its    *)
(* budget back, and writes the result to the spool of its member. A spool *)
(* in memory takes budget for each chunk without waiting: when there is   *)
(* none, it moves to disk and gives its budget back. When the last chunk  *)
(* of a member is in its spool, and the reader has finished it, the       *)
(* member goes to a queue of Workers places. One emitter writes each      *)
(* member to the archive, and gives the budget of its spool back.         *)
(*                                                                         *)
(* Each budget unit is one chunk. A compressed chunk is as long as its    *)
(* plaintext: the worst case.                                              *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    Members,          \* the number of members
    Chunks,           \* the chunks of each member
    Workers,          \* the workers, and the places of each queue
    Limit,            \* the budget, in chunks
    SpillBeforeWait,  \* the reader moves its member's spool to disk before it waits
    SpoolWaits        \* a spool waits for budget, and does not move to disk

M == 1 .. Members
W == 1 .. Workers

VARIABLES
    used,       \* the budget in use
    rpc,        \* the step of the reader
    rm,         \* the member that the reader reads
    rc,         \* the chunks of rm that it read
    held,       \* the reader holds back a chunk that it read
    queue,      \* the chunks for the workers: <<member, ...>>
    wpc,        \* worker -> "idle", "busy", "settle" or "send"
    job,        \* worker -> the member of its chunk
    left,       \* member -> the claims on it: the reader's and its chunks'
    spool,      \* member -> "mem" or "disk"
    reserved,   \* member -> the budget that its spool holds
    done,       \* the complete members, for the emitter
    emitted     \* the members written to the archive

vars == <<used, rpc, rm, rc, held, queue, wpc, job, left, spool, reserved, done, emitted>>

Init ==
    /\ used = 0
    /\ rpc = "acquire" /\ rm = 1 /\ rc = 0 /\ held = FALSE
    /\ queue = <<>>
    /\ wpc = [w \in W |-> "idle"] /\ job = [w \in W |-> 0]
    /\ left = [m \in M |-> 1]
    /\ spool = [m \in M |-> "mem"] /\ reserved = [m \in M |-> 0]
    /\ done = <<>> /\ emitted = 0

Free(n) == used + n <= Limit

(***************************************************************************)
(* The reader.                                                             *)
(***************************************************************************)

\* Take one chunk of budget without waiting. If there is none, move the
\* member's own spool to disk first, then wait.
Acquire ==
    /\ rpc = "acquire"
    /\ IF Free(1)
       THEN used' = used + 1 /\ rpc' = "read"
            /\ UNCHANGED <<spool, reserved>>
       ELSE IF SpillBeforeWait /\ spool[rm] = "mem"
            THEN /\ used' = used - reserved[rm]
                 /\ reserved' = [reserved EXCEPT ![rm] = 0]
                 /\ spool' = [spool EXCEPT ![rm] = "disk"]
                 /\ rpc' = "wait"
            ELSE rpc' = "wait" /\ UNCHANGED <<used, spool, reserved>>
    /\ UNCHANGED <<rm, rc, held, queue, wpc, job, left, done, emitted>>

Wait ==
    /\ rpc = "wait" /\ Free(1)
    /\ used' = used + 1 /\ rpc' = "read"
    /\ UNCHANGED <<rm, rc, held, queue, wpc, job, left, spool, reserved, done, emitted>>

\* Read a chunk. The chunk held back goes to the queue, and the new one is
\* held back. At the end of the member, the read gives nothing, and its
\* budget goes back.
Read ==
    /\ rpc = "read"
    /\ IF rc < Chunks
       THEN /\ rc' = rc + 1
            /\ IF held THEN (rpc' = "submit" /\ UNCHANGED held)
                       ELSE (rpc' = "acquire" /\ held' = TRUE)
            /\ UNCHANGED used
       ELSE /\ used' = used - 1 /\ rpc' = "final" /\ UNCHANGED <<rc, held>>
    /\ UNCHANGED <<rm, queue, wpc, job, left, spool, reserved, done, emitted>>

Submit(to) ==
    /\ Len(queue) < Workers
    /\ queue' = Append(queue, rm)
    /\ left' = [left EXCEPT ![rm] = @ + 1]
    /\ rpc' = to

SubmitHeld ==
    /\ rpc = "submit" /\ Submit("acquire")
    /\ UNCHANGED <<used, rm, rc, held, wpc, job, spool, reserved, done, emitted>>

SubmitFinal ==
    /\ rpc = "final" /\ Submit("claim") /\ held' = FALSE
    /\ UNCHANGED <<used, rm, rc, wpc, job, spool, reserved, done, emitted>>

NextMember == rm' = rm + 1 /\ rc' = 0 /\ rpc' = IF rm = Members THEN "end" ELSE "acquire"

\* The reader drops its claim. If every chunk is in the spool, the member
\* is complete, and the reader sends it to the emitter.
Claim ==
    /\ rpc = "claim"
    /\ left' = [left EXCEPT ![rm] = @ - 1]
    /\ IF left[rm] = 1 THEN rpc' = "send" /\ UNCHANGED <<rm, rc>> ELSE NextMember
    /\ UNCHANGED <<used, held, queue, wpc, job, spool, reserved, done, emitted>>

SendDone ==
    /\ rpc = "send" /\ Len(done) < Workers
    /\ done' = Append(done, rm)
    /\ NextMember
    /\ UNCHANGED <<used, held, queue, wpc, job, left, spool, reserved, emitted>>

(***************************************************************************)
(* The workers and the emitter.                                            *)
(***************************************************************************)

Take(w) ==
    /\ wpc[w] = "idle" /\ queue # <<>>
    /\ job' = [job EXCEPT ![w] = Head(queue)] /\ queue' = Tail(queue)
    /\ wpc' = [wpc EXCEPT ![w] = "busy"]
    /\ UNCHANGED <<used, rpc, rm, rc, held, left, spool, reserved, done, emitted>>

\* Compress, then give back the budget of the chunk before the spool needs
\* its own.
Compress(w) ==
    /\ wpc[w] = "busy"
    /\ used' = used - 1
    /\ wpc' = [wpc EXCEPT ![w] = "settle"]
    /\ UNCHANGED <<rpc, rm, rc, held, queue, job, left, spool, reserved, done, emitted>>

\* Write the chunk to the spool of its member. A spool in memory takes one
\* chunk of budget, or moves to disk. The member is complete when its last
\* claim goes.
Settle(w) ==
    LET m == job[w] IN
    /\ wpc[w] = "settle"
    /\ \/ spool[m] = "disk" /\ UNCHANGED <<used, spool, reserved>>
       \/ spool[m] = "mem" /\ Free(1)
          /\ used' = used + 1 /\ reserved' = [reserved EXCEPT ![m] = @ + 1]
          /\ UNCHANGED spool
       \/ spool[m] = "mem" /\ ~Free(1) /\ ~SpoolWaits
          /\ used' = used - reserved[m] /\ reserved' = [reserved EXCEPT ![m] = 0]
          /\ spool' = [spool EXCEPT ![m] = "disk"]
    /\ left' = [left EXCEPT ![m] = @ - 1]
    /\ wpc' = [wpc EXCEPT ![w] = IF left[m] = 1 THEN "send" ELSE "idle"]
    /\ UNCHANGED <<rpc, rm, rc, held, queue, job, done, emitted>>

Send(w) ==
    /\ wpc[w] = "send" /\ Len(done) < Workers
    /\ done' = Append(done, job[w])
    /\ wpc' = [wpc EXCEPT ![w] = "idle"]
    /\ UNCHANGED <<used, rpc, rm, rc, held, queue, job, left, spool, reserved, emitted>>

Emit ==
    /\ done # <<>>
    /\ used' = used - reserved[Head(done)]
    /\ reserved' = [reserved EXCEPT ![Head(done)] = 0]
    /\ done' = Tail(done) /\ emitted' = emitted + 1
    /\ UNCHANGED <<rpc, rm, rc, held, queue, wpc, job, left, spool>>

Finished == emitted = Members /\ UNCHANGED vars

Next == Acquire \/ Wait \/ Read \/ SubmitHeld \/ SubmitFinal \/ Claim \/ SendDone
        \/ Emit \/ Finished
        \/ \E w \in W : Take(w) \/ Compress(w) \/ Settle(w) \/ Send(w)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

TypeOK ==
    /\ used \in 0 .. Limit + Workers
    /\ rm \in 1 .. Members + 1

\* The budget is never over its limit.
WithinLimit == used <= Limit

\* At the end, each unit of budget is back.
NothingLeaks == emitted = Members => used = 0

\* Every member reaches the archive: the build never stops for ever.
Terminates == <>(emitted = Members)
=============================================================================
