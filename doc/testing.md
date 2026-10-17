# eictar — Testing

Date: 2026-10-15
Applies to: v1 (format version 1.0)

This document describes how eictar is tested, and the evidence that the
tests give. `design.md` describes the format and the program, and
`history.md` gives the milestones and the releases. This document was §13
of `design.md` until 2026-10-15. Its section N was section 13.N there.

## Contents

[1. Unit tests](#1-unit-tests-in-each-package-go-test-) ·
[2. Operational tests](#2-operational-tests-end-to-end-build-tag-operational) ·
[3. Supporting tools](#3-supporting-tools) ·
[4. Stress tester](#4-stress-tester) ·
[5. Assurance plan](#5-assurance-plan)


Tests are part of each deliverable. There are two levels: unit tests next to
the code, and operational tests that run the built binary as a user does. A
milestone in history.md is not complete until both levels cover it.

Every item in the lists below exists now, except the items marked "later".

## 1. Unit tests (in each package, `go test ./...`)

- **Format round trip**: members of all types, every codec, plaintext and
  encrypted, index sealed and not sealed.
- **Structure encoding**: encode and decode of the header, the trailer and the
  crypto header, every CRC, every limit, and the refusal of each single-field
  corruption.
- **Codec conformance**: one test suite for every registered codec. It covers
  round trips, empty input, incompressible input, chunk boundaries, the
  parameter checks, refusal of bad parameters, and the parallel-encoder test
  of design.md §8.2.
- **Key schedule**: fixed vectors for the KEK, the wrapped data key, and
  every subkey. Also for a sealed chunk, a sealed index, a sealed dictionary
  and the keyed index digest. A failure here means that existing archives no
  longer open.
  It never means "update the vector". The vector of the dictionary key was
  also calculated apart from the code, from the definition in
  `doc/format.md`.
- **Chunked AEAD**: tag checks, a wrong key, a chunk moved to another index or
  member, a changed final flag, and truncation. Each must fail.
- **Crafted archives**: the reader must refuse each of these:
  - a member path with `../`, or an absolute path
  - a link to a place outside the destination, followed by a write through it
  - a large chunk size
  - a blob outside the body
  - a regular file without a digest
  - a member that shares content with a member of other content, or with
    no blob
  - a dictionary that the index does not hold, or on a codec other than zstd
  - KDF parameters above the limits
  - a downgrade to plaintext
  - changed metadata in an encrypted archive

  The crafted-KDF test fails if the check is removed. This proves that the
  test catches the fault.
- **Path rules**: `StorePath`, `IsStoredPath` and `Match`, with hostile inputs:
  `../` escapes, absolute paths, and paths that are not canonical.
- **Fuzzing** (`go test -fuzz`): the header, the trailer, the crypto header,
  the index decoder, the decoders of the codecs, the openers of a sealed
  chunk, index and dictionary, whole archives changed from the golden ones,
  the pattern rules, the compression spec and the configuration file. A
  malformed archive must give an error. It must never cause a panic or an
  unbounded allocation. §5, step 4, gives the rule of each target.
- **Race**: all tests under `-race`, with `-j` from 1 to 64.
- **Configuration**: the precedence of the four levels, codec defaults, and
  the search order of the files. Unknown keys and variables are usage errors
  that name their line or variable, and so are a passphrase and the other
  refused keys. Also: the scope of a configured value, a group-writable file,
  `--no-config`, comments, `--show-config` with its sources, and the
  variable of `--passphrase-env`. A `.eictarrc` in the current directory has
  no effect.
- **Encoder memory** (design.md §8.2):
  - the window of zstd fits the chunk
  - the estimate of each codec
  - a limit on the compressions at once
  - the number of states for each amount of RAM and each memory limit
- **Codecs, worst case**: each codec at its strongest setting compresses
  4 MiB of zeroes in less than 10 s. The test proves why the xz binary tree
  is not used (design.md §10.2).
- **Lock**: while one writer holds an archive, append, delete, compact,
  repair and create each stop with `ErrLocked`. A lock on a file that a
  rename replaced is refused (design.md §9.6).
- **Recompress**: the content, the digests and the ids stay, and each sealed
  member gets a new salt. A tombstone behind a hardlink, and the holes of a
  sparse file, survive (design.md §9.3).
- **Progress meter**: the status line, no drawing before the first byte, and
  no meter without a terminal (design.md §10.10).
- **Compare with the disk**: each kind of difference, patterns and excludes,
  a file archived alone, an encrypted archive, the same result for each
  `-j`, and a link on disk that leads out of the directory (design.md §9.8).
- **Dry run**: for create, update with each mode, extract with each
  overwrite policy, and delete, the paths of the dry run are the paths that
  the real run writes, and the archive does not change. Also the conflict
  policies, the key for the digests of an encrypted archive, an unsafe
  member path, and no destination made (design.md §9.9).
- **Strip components**: the paths after the strip, a short path left out,
  the later member of a collision with its warning, two directories with
  one path, a hard link to a target that is extracted and to one that is
  not, patterns on the archive paths, the dry run, `--diff` with patterns,
  excludes and a hard link, a path that is not canonical, and exit 1
  (design.md §10.14).
- **Security regressions**: one test for each finding of
  `doc/Security_Audit.md`:
  - the decision for each class of xattr
  - a member `.`
  - a file that becomes a link after the walk
  - a directory that becomes a link during the walk, before and after the
    walk opens it
  - the rule for links in the archive path
  - the umask
  - the expansion of the index
  - a passphrase file that other users can read
- **Names on the terminal**: each kind of escape of design.md §10.13. A name with an
  escape sequence in `-t`, `-tv`, a dry run and `--diff`: escaped on a
  terminal, and exact to a pipe. A message is escaped in both cases.
- **Man page and help**: `doc/eictar.1` and `--help` name every long option
  of the parser, and the help gives each short form. No line of the help is
  wider than 80 columns.
- **Platforms**: each metadata test runs where `meta.Supports` says that its
  feature exists. An xattr from macOS and one from Linux, extracted on each
  platform, are applied or listed in the one notice as design.md §7.7 says. A pipe is
  created, or skipped with a notice on macOS.
- **Golden files**: four archives in
  `src/internal/archive/testdata/golden/`. `plain.ect` and `encrypted.ect`
  each have three generations: a create, an append that replaces a member,
  and a delete. `dict.ect` is encrypted, with a sealed dictionary.
  `shared.ect` has a reference to a live owner and a reference to a
  tombstone. The tests open them, run `--verify` on them and extract them.
  Only a planned format change can write them again, with `-update-golden`.
- **Dictionaries** (design.md §4.2):
  - a gain on similar files
  - a frame that decodes only with its own dictionary
  - a dictionary within its size, and training that fails cleanly
  - reuse on `-r`, compact and recompress
  - damage to a plain and to a sealed dictionary
- **Identical content** (design.md §4.3):
  - copies that share one blob, and `--no-dedup`
  - sharing across generations, and with an earlier version
  - a damaged old owner, which is not used
  - delete, compact and recompress
- **Selection**: `-R` and `--exclude-regex` on the walk and on each read, a
  whole-path match, and an `-R` that matches nothing. An `--exclude` glob
  with a `/` takes the contents of a directory on a read, for `-t` and
  `--diff` (design.md §10.11). The `.ect`
  name rule (design.md §10.12).
- **Mutation**: append after the old trailer, each `--on-conflict` policy,
  and each `--update-mode` case of design.md §10.5. Also delete, `--verify`, `--info`,
  and the passphrase for each. Compact runs plain and encrypted, through a
  symbolic link, and with a hardlink to a tombstone. Two tests check
  `--keep-going`. A path that fails keeps its old member. A hardlink never
  points to a member that failed.
- **Crash consistency**: an append, cut at each byte between the old and the
  new length. Each cut must fail to open, and `--repair` must give back the
  old file exactly. A torn trailer gives the same result. The writer only
  appends, and it syncs before the trailer. Thus a crash leaves a prefix of
  the writes, and the cuts cover each crash point.

## 2. Operational tests (end to end, build tag `operational`)

These tests run the compiled `eictar` binary in a temporary directory. They
check its exit status, its output and the resulting files. They never call
internal packages. They prove that the program works, not only that its
parts work.

- **Lifecycle**: create, list and extract, with a comparison against the
  original tree. Then append (with other codec settings), delete, `--info`,
  `--verify`, compact and `--verify` again, plain and encrypted.
- **Concurrency**: the same input at several `-j` values gives the same
  content and the same listing.
- **Encryption**: round trips with a sealed and with a plain index. A wrong
  passphrase gives exit 3. With no passphrase and no terminal, the message
  names the options to use. The environment-variable source works, with its
  warning. A plaintext archive with a passphrase source gives exit 3.
- **Paths and links**: stripped absolute paths, `-d`, the archive that
  contains itself, symbolic links, and `-h`.
- **Damage**: a changed byte gives exit 3, and a missing archive names the
  file.
- **Update modes**: a touched file that `digest` skips and `newer` takes.
  The unit tests of §1 cover each mode and case.
- **Mixed archives**: members from separate appends, with different codecs
  and parameters, all extracted in one pass.
- **Refused mutations**: `--on-conflict=error` and a `--delete` pattern with
  no match give exit 2, and the archive is unchanged.
- **Listing**: `-t` gives the paths, and `-tv` and `--long` give the same
  long listing. `-tvv` adds its columns and the line of totals. `--json` has
  every field of design.md §10.9.
- **Metadata**: hardlinks, holes, xattrs, setuid bits, pipes, link times, a
  skipped socket, and difficult names (spaces, newlines, non-UTF-8, long
  names, leading dashes). The test compares the result with `os.Stat`, xattr
  reads and the allocated blocks, so that holes stay holes. It runs with a
  plain and with an encrypted archive. The ownership and device tests need
  root, and skip with a reason when the user is not root.
- **Crash consistency**: a real append is killed with `SIGKILL` part way
  through. The list must fail with exit 3 and name `--repair`. Then
  `--repair` must give back the old file exactly.
- **`--verify`**: a changed byte in a blob gives exit 3, and the message
  names the member. `--quick` passes, because it reads no member data.
- **Configuration**: a configuration file in `HOME` sets the codec, `-v`
  names the file, a misspelled variable gives exit 2, and `--show-config`
  runs with no operation. The unit tests cover the refusals. A file that
  another user owns needs a second user, so no test covers it yet.
- **Lock**: two real appends at the same time. The second stops with exit
  4, and the first completes.
- **Every codec**: members from six codecs in one archive, from separate
  appends. One pass lists them, one runs `--verify`, and one extracts them.
- **Recompress**: a bad spec gives exit 2 and changes nothing. A good one
  changes the codec of every member, and the extracted tree is the same.
- **Progress**: with stderr not a terminal, `--progress` writes nothing
  there.
- **Change of passphrase**: the new passphrase opens the archive, the old one
  gives exit 3, and the new KDF parameters are in effect.
- **Newer features**:
  - `-R` on create and on extract
  - the `.ect` name
  - a dictionary, in `--info` and in the listing
  - shared content, in the listing, in `--info` and in `--json`
  - `--diff`: no difference after `-xp`, except the pipe on macOS, and then
    a changed file and a missing file with exit 1 (design.md §9.8)

  The dry run (design.md §9.9) has no operational test. The tests of package `cli`
  run it through `Run`, and check its output and that nothing changes.
- **Large archive**: an archive larger than 4 GiB, plain and encrypted.
  `make large` runs it. Other runs skip it, because it needs time and disk
  space. The format stores offsets and lengths as CBOR uints, which take 8
  bytes above 2^32. The test takes each of these past 2^32: the size of one
  member, the offset of a blob, the offsets of data segments in a sparse
  file, the index offset, and `prev_index_offset`. The data is random and
  the codec is `none`, so the archive is as large as its data. The test
  checks the sizes in `--json`, `--verify`, a full extraction, `-O`,
  `--diff`, an append, a cut append and `--repair`, and a delete with
  `--compact`. It compares each file with SHA-256. A reader that keeps only
  32 bits of a blob offset fails `--verify` in this test.
- **Scale** (nightly, later): 100,000 small files, and one file larger than
  memory.

## 3. Supporting tools

- `src/internal/testutil/` holds the fixture-tree builder, the tree
  comparison, and a helper that builds the binary once for each test run.
- **Code builds the fixtures.** They are not committed as a tree, because git
  cannot keep modes, timestamps, hardlinks and holes exactly.
- **Tests that need root** (ownership, device nodes) skip with a clear
  reason. A CI container with the necessary privilege must run them.
- **A skip passes quietly.** `go test` does not show it without `-v`, and a
  platform avoids a test by skipping it. Thus `make skips` runs the tests
  with `-json`, and `tools/testskips` lists each skipped test with its reason,
  each failed test with its output, and the totals. A package that fails
  outside a test, as after a time-out, is listed with its output. Each CI
  job runs it after `make check`, so that a green job also says what it did
  not test, and a red job says which test failed, when it fails again in
  this second run. The job's result stays the result of `make check`.
- **Coverage and mutation testing** measure the tests (§5). `format`,
  `crypt` and `codec` need the strongest tests, because a fault there is
  silent and permanent. The benchmarks are `make bench` and `make compare`
  (design.md §8.4).
- **References to sections stay correct.** The code and the documents
  refer to sections by number, such as `doc/design.md 9.6` in a comment
  and `testing.md §5` in a document. A section that moves leaves such a
  reference wrong. The test of `tools/docrefs` finds each reference, in
  the documents, the code, the `Makefile` and the workflows, that names a
  section or a document that is not there. A reference with no name of a
  document is to the document that holds it. In `Security_Audit.md`, it is
  to `design.md`.


## 4. Stress tester

`make stress` builds and runs `tools/stress`, and `make stress-build` builds
it alone, as `.build/stress`, with `.build/eictar-faults`: eictar built with
`-tags faultinject`, for the disk faults. It tests the built binary with random data
and random operations, and it compares each result with a model. The unit
and operational tests check the cases that someone thought of. The stress
tester finds the combinations that nobody did.

**The model** is a map from each stored path to what an extraction must give
back. That is the type, the content, the size, the mode, the time, and the
target of a link. It changes only as eictar's rules say (design.md §9.2, §10.5).
Replace, skip, error, the three update modes, and delete with eictar's
pattern rule are each a few lines of the tester.

**A sequence** creates an archive from a generated tree, and then takes steps.
Before most steps, the tree changes. A file gets new content, a new time or
a new mode, or it goes, or it becomes a link, or new entries come. Then one
operation runs: append with each `--on-conflict`, update with each
`--update-mode`, delete, compact, compact with `--recompress`, extraction
by pattern or by `-R`, `--diff`, a dry run, or `--strip-components`. Each
operation uses a random codec and random settings: chunk size, workers,
memory limit and spill threshold. A zstd dictionary at level 10 or above
gets chunks of 64 KiB or more. Each chunk with such a dictionary costs
approximately 0.5 ms (design.md §15.2), and chunks of 512 bytes on a large tree take
more than the limit of two minutes for one command, which counts as a hang.

The last three steps test the operations that compare and plan:

- **`--diff`** of a tree just extracted must find no difference. Then the
  tester makes one change to that tree: other bytes of the same size, a
  mode, a time, a file removed, a file added, or another link target. It
  keeps the time of the parent directory. `--diff` must then report that
  path with that kind of difference, and nothing else, with exit 1.
- **A dry run** of `-r`, `-u`, `--delete` or `-x` must list the paths that
  the model says the real run writes or deletes. The archive must not
  change, and `-x -n` must not make its destination.
- **`--strip-components`** 1 or 2: half the time, the tester first appends
  a twin of an entry under a new top directory, so that two members get one
  path. The model gives the expected tree and the collisions. The dry run
  must list the paths after the strip, the extraction must give the
  expected tree, and `--diff` with the option must find no difference.
  Each must warn for each collision and exit with 1 when there is one.

**Each sequence has a profile,** the kind of tree that it works on. The seed
chooses it, and `-profile` forces one:

| Profile | Tree | What it takes eictar through |
|---|---|---|
| `mixed` | 10 to 70 entries of every kind and size | the general case |
| `small` | 150 to 500 small source files that share a header and a shape | dictionaries that train, many members |
| `large` | 3 to 6 files of 1 to 24 MiB, and copies of them | many chunks, chunks of 16 and 32 MiB, windows, shared content |
| `versions` | medium files with exact copies, and near-copies with a few bytes changed | shared content that must tell equal from almost equal |

**The settings vary with the features.** A zstd codec can have `train`:
with a small size, alone, or at 1 MiB. It can have `long`: alone, or with a
window that a large chunk holds. `-r` and `-u` can have `-R`,
`--exclude-regex` and `--no-dedup`, and create can have `--no-dedup`. The
model applies `-R` and `--exclude-regex` as eictar does. An `-R` that matches
nothing must be refused like a conflict.

At the end of each sequence, `--info` shows whether the archive holds a
dictionary and shared content. The summary counts both, so that the coverage
of these features is measured, not assumed.

A third of the sequences are encrypted, some with a sealed index. In these, a
step can also change the passphrase. After the change, the old passphrase
must fail with exit 3.

**After each step** the tester makes five checks:

1. `-t` lists exactly the model's paths.
2. `--verify` passes.
3. A full extraction gives back the model. The only extra paths allowed are
   the parent directories that extraction makes itself.
4. The hardlinks of the extraction agree with the model. The model gives
   each file a link group. One run puts the names of one inode that it
   stores into one group. The names of a group must be one file, and the
   names of two groups must be two files. Each extraction of the tester
. The second reader (§5, step 2) agrees. Its fields are those of
   `-t --json`, and its own extraction gives back the model.

Some operations must be refused: a conflict under `--on-conflict=error`, an
`-R` that matches nothing, and a delete pattern that matches nothing. Each
must exit with 2, and must leave the archive byte for byte as it was.

**The data** is random, text-like, repetitive or zeros, and it is often one
byte on either side of a chunk boundary. The tree has deep directories, empty
files, symbolic links, hardlinks, copies and sparse files. Its names have
spaces, other scripts, and bytes that are not UTF-8 where the filesystem
takes them. A name never holds a glob character, so that a path is a literal
pattern.

**The fault mode** is on by default. It adds three tests:

- **A crash.** After a change, the tester cuts the archive at a random point
  inside the new generation. The archive must be refused with exit 3 and a
  message that names `--repair`. Then `--repair` must give back the archive
  of before the change, byte for byte.
- **Damage.** In a copy of the archive, the tester flips one to four bits,
  often in the index and the trailer. `--verify` and extraction must agree.
  Both must refuse the copy with exit 3. Otherwise both must accept it and
  give back the model exactly, because a bit in dead space harms nothing.
  Wrong content with exit 0 is the failure that this test looks for.
  The second reader must refuse the copy when eictar refuses it, and read
  each member when eictar accepts it.
- **A disk fault.** The tester runs a change to the archive with
  `.build/eictar-faults`, and `EICTAR_FAULT` makes one operation on the
  archive file fail: the Nth open, create, write, short write, `fsync`,
  truncate, close, rename, remove or `fsync` of the directory. The change is
  an append, a delete, a compact, a recompress or a change of passphrase. A
  command that succeeds must leave the new state. A command that fails must
  exit with 4, and leave the old state or the new one, with no file beside
  the archive, except a temporary file whose removal was the fault. A
  change that commits with a rename must leave the old archive byte for
  byte, or the new one. A change in place may need `--repair`, which must
  then give back one of the two. One fault does not stop the rollback of a
  change in place, so that needs two faults or a crash after one, which the
  crash model of §5 covers. The tester prints a note and leaves the disk
  faults out when the binary is not there.

Any other exit code, a panic, or a command that runs for more than two
minutes is a failure.

**The summary** starts with the result: `PASS`, or `FAIL` with the sequence.
Then it gives each check, and the number of times that it held. A check
that the run did not reach has the note `[not reached in this run]`. Then it
gives the number of each operation, and the coverage of the profiles,
dictionaries and shared content. Last, it gives the five slowest commands
of the run. Each line has the time, the options, the size of the source
tree, and the `make stress` command that repeats its sequence. A slow
command is not a failure. Only a command that takes more than two minutes
fails, as a hang. The list shows a slow case before it becomes a hang, as
the case of design.md §15.2 became. After a failure, the counts are the checks
that held before it. To a file or a pipe, the progress line comes once a
minute.

**A failure stops the run.** The sequence's directory stays, with the source
tree, `failure.txt` and `replay.sh`. `failure.txt` gives the seed and each
step. `replay.sh` repeats the eictar commands. All randomness comes from the
seed, and the file times come from a clock of the tester, never from the
system clock. Thus `make stress STRESS="-seed N -sequences 1 -profile P"`
repeats a failed sequence exactly.

**The tester is tested.** A bug put into eictar on purpose, where `-u` took
an equal time as newer, failed the sixth sequence. The report named the file
and its wrong mode.

**Findings.** The first runs found three faults in eictar. Each one now has
a test of its own:

- A chunk that its codec refused, for example after a failed zstd checksum,
  gave exit 4, as for an I/O error. It must give exit 3, for damage. Such an
  error is now `ErrCorruptData`.
- A pattern that matched a directory by its name, deeper in the tree, did
  not take the directory's contents (design.md §10.11).
- `-u --update-mode=digest` archived an unchanged sparse file again, when the
  filesystem reported its data regions in another way (design.md §10.5).

The steps for `--diff`, `-n` and `--strip-components` found two more in
their first runs:

- `--diff` reported the directory of a member as a path that the archive
  lacks, when `-r a/b/c` had added the member by its own path, with no
  member for `a/b` (design.md §9.8).
- `--diff --strip-components` compared a hard link with the file at its
  target's path when a collision had left the target out. Extraction gives
  such a link a copy of the content (design.md §10.14).

Longer runs found one more fault, and two faults in the tester:

- A damaged crypto header that gave less than 8 KiB of KDF memory for each
  thread gave exit 4. It must give exit 3, for damage (design.md §6.2).
- `zstd:level=13,train=16K` with chunks of 512 bytes took 124 s on a tree of
  125 MiB, and the tester reported a hang. The output was correct. At
  level 9, the same command took 0.6 s. This is the cost that design.md §15.2 records.
- After 4 hours, the generator gave two new entries of one directory the
  same name, and the second one failed. A new entry now gets another name
  when its name is taken. After this fix, a run of 8 hours passed. `make
  check` now runs the tests of `tools/` too.

A run of ten minutes, over all the profiles, made 146 sequences. They ran
approximately 14,000 eictar commands, with 256 crashes and 510 damaged
copies. 51 sequences ended with a dictionary, and 124 with shared content.
With the new steps, a run of five minutes made 106 sequences and 10988
commands. It ran 207 `--diff` steps, 305 dry runs and 161 extractions with
`--strip-components`.

## 5. Assurance plan

**The goal is evidence that eictar can hold data in a mission-critical
use.** Tests cannot prove that a program is correct. Thus this plan collects
evidence of different kinds, and each kind finds faults that the others do
not find:

- the strength of the tests, measured
- a second implementation, from the specification only
- faults of the disk and of the machine, injected on purpose
- hostile input, generated
- models of the protocols, checked by a tool

The critical promise is that a user gets back the data that went in, or
gets an error. Wrong data with exit 0 is the worst failure. Each step below
tests that promise from a different side.

**Step 1. Measure the strength of the tests.**

- **Coverage of all the tests together.** Unit coverage alone does not
  count the operational tests, because they run the binary. `make cover`
  builds the binary with coverage, runs the unit tests and the operational
  tests, and merges the two results.
- **Tests as root.** Linux and macOS run the tests as an ordinary user, and
  the BSD virtual machines run them as root. A CI job runs the tests on
  Linux as root too. Then each platform family runs the code for the owner,
  the device nodes and the privileged xattrs at least once.
- **Mutation testing.** `tools/mutate` makes one small change to the code at
  a time: a comparison, an operator, or a condition. Then it runs the tests.
  A change that no test finds is a *survivor*. A survivor in code that the
  tests run is a check that no test checks. `make mutate` runs it.

The result of step 1 is a list of gaps, in order. That list decides where
steps 2 to 4 start.

**How `tools/mutate` works.** It parses each file of the package that builds
on this platform. It makes these changes, one at a time:

- a comparison to its boundary and to its opposite (`<` to `<=` and `>=`)
- `==` to `!=`, `&&` to `||`, and the reverse of each
- an arithmetic, bitwise or shift operator to its pair (`+` to `-`, `<<` to
  `>>`)
- a `!` removed, and `++` to `--`
- the condition of each `if` to `false`, so that its check never runs

A run of the tests first gives the coverage. A mutant in code that no test
runs is *not covered*, and its tests do not run. A coverage profile has no
block for the expressions of a `case`, for a declaration outside a
function, or for the rest of a statement after a function literal in it.
Thus a case expression takes the coverage of its `switch`, a declaration
outside a function always counts as run, and the rest of a statement takes
the coverage of its start. The last rule came late: in
`if err := applyOwner(m, func(…) {…}); err != nil {`, the condition showed
as not covered, and the accepted list hid it. Each other mutant goes to
the compiler through an overlay in `GOFLAGS`, so the source tree never
changes, and mutants run in parallel. A `go build` that a test runs
inherits `GOFLAGS`. Thus the binary that the operational tests build has
the mutant too, and with `-tags operational` and `-test` for their
package, they count. With `-tags`, a second run without a mutant gives
the coverage of that binary: it writes it to `GOCOVERDIR`, as for `make
cover`, and the tool adds it to the coverage of the tests. A second run
is necessary, because with `-cover`, `go test` gives each test process a
coverage directory of its own. Each `go` command runs in a process group of
its own, and the tool kills the group when the command ends. A mutant can
make the binary loop for ever, and when its test stopped at the time
limit, the binary stayed: one run left 18 of them, each on a core. A failed test finds the mutant. A test binary that does not end
in three times the time of the first run stops, and that also finds the
mutant. With `-j`, the mutants share the machine, so a slow run can pass
that limit with no hang. Thus each mutant that stops runs again alone, and
only a second stop finds it. On `archive`, before this rule, 156 of 388
mutants stopped under `-j 8`. A mutant that does not compile does not count. The score is the
part of the counted mutants that the tests find. `-test` gives other
packages whose tests run, so that a run can tell a gap of one package from a
gap of the whole program.

**The accepted list.** Some mutants cannot be found by any test, or by
no test of a run of `make mutate`. `tools/mutate/accepted.txt` lists them,
and `make mutate` does not count them. An entry names the file, the
function and the change, in the form that the report prints. Thus an entry
stays correct when lines move. Each entry must give one of four reasons:

- *Equivalent:* the change cannot change what eictar does, for example the
  error of `crypto/rand.Read`, which never returns one.
- *Too costly:* a test needs what a unit test cannot have: more memory
  than a test can use, a file system on which a given call fails, or a
  count of the open descriptors of the process. The entry says what the
  test needs, and names what else stops the input or covers the risk.
- *Needs root:* only root can run the code, such as a device node or an
  owner, and `make mutate` does not run as root. The entry names the test
  that the CI job as root runs.
- *Another platform:* the code runs only on a platform where `make mutate`
  does not run. The entry names the platforms.

An entry whose mutant the tests find, or that names no mutant, fails the
run. Thus the list cannot keep an entry that is no longer true.

**The first results, with the tests of the package itself:**

| Package | Mutants | Found | Survived | Not covered | Score |
|---|---|---|---|---|---|
| `format` | 396 | 246 | 73 | 70 | 63.2% |
| `crypt` | 88 | 48 | 35 | 4 | 55.2% |
| `pipeline` | 179 | 102 | 59 | 12 | 59.0% |

With the tests of `archive` too, `format` gets 68.4% and `pipeline` 70.5%.
Thus most of the gaps are gaps of the whole program. The coverage of the
unit and the operational tests together is 90.3%, and the operational tests
raise `cli` from 86.8% to 95.3%.

The survivors fall into these groups, in order of risk:

1. **Checks of a hostile archive that no test makes fail.** No test of
   any package finds the removal of these checks of the crypto header: the
   version, the KDF, the cipher, `recipients`, and the lengths of the salt
   and the wrapped key. The same is true for these checks of the index: an
   unknown member type, a field on the wrong type, the chunk table, and a
   sparse segment that overflows. Fuzzing finds a panic, but it does not
   find a check that is gone.
   *Done.* Each case of the index tests now names the check that must
   refuse it, so that a later check cannot hide a check that is gone. A
   reader also decodes each bad index, and a test of each crypto header
   field changes that field only. This work found two rules of
   `doc/format.md` that the validator did not apply:
   - one chunk for an empty payload. format.md §5 says that the last chunk is never
     empty.
   - `chunk` on a member that is not `reg`, or on an empty payload (format.md §5,
     §8.3).

   The validator refuses them now. No version of eictar wrote these
   shapes, so each archive that eictar wrote still opens. The work also
   found that the writer does not obey format.md §8.3: it puts `off`, with `len` 0,
   on a directory, a link, a device and an empty file. After 1.1.0, the
   writer, compact and recompress do not write it. format.md §8.3 now says
   that a reader accepts it and ignores it, because the archives of 1.1.0
   and earlier have it. `TestNoOffsetWithoutABlob` and a validator test
   keep both rules.
2. **Limits that no test reaches exactly.** `>` to `>=` survives at each
   limit: `MaxIndexSize`, `MaxIndexMembers`, `MaxDicts`, `MaxXattrs`, the
   xattr name and value, the chunk size, the KDF time and memory, and the
   bounds of the trailer.
   *Done.* A test accepts each limit at its exact value, and an earlier
   test refuses the value one past it. The cap on the pairs of a CBOR map
   has a test too. `MaxIndexSize` and `MaxIndexMembers` are in the
   accepted list: a test needs more than 1 GiB, and another check stops
   the same input first.
3. **The key schedule above generation 255.** `uint64LE` survives with `>>`
   changed to `<<`, because each test vector uses a generation below 256.
   An index key of a later generation has no fixed vector.
   *Done.* A test computes each key of `doc/format.md` §7.1, and the index
   digest, with the standard library only. It uses generations whose eight
   bytes are all in use. A vector pins generation `0x0102030405060708`.
4. **Errors of the disk in the pipeline.** No test makes a write, a seek or a
   spill of a spool fail. The v1.0.8 hang was in this code. Step 3 covers it.
   A sparse file that changes while it is read is also not tested
   (`builder.go`).
   *Done* in step 3, with a test of the sparse file.
5. **Equivalent mutants.** Some changes cannot change the result: the
   capacity of a `make`, or the error of `rand.Read`. A list of the accepted
   survivors, each with its reason, is necessary before the release gate can
   ask for zero survivors.
   *Done.* The accepted list has 24 entries for `format`, 9 for `crypt`
   and 21 for `pipeline`. Before an entry went in, new tests found each
   mutant that a test can find: for example, a failed seal in
   `Index.Encode`, `SameCodec`, and a sealed index larger than 40 bytes.

**The results now, with the tests of the package itself:**

| Package | First score | Raw score now | Accepted | Not explained |
|---|---|---|---|---|
| `format` | 63.2% | 94.0% | 24 | 0 |
| `crypt` | 55.2% | 89.7% | 9 | 0 |
| `pipeline` | 59.0% | 88.3% | 21 | 0 |
| `archive`: `writer.go`, `reader.go`, `fs.go` | 77.4% | 91.6% | 31 | 0 |
| `archive`: `extract.go` | 62.1% | 91.6% | 27 | 0 |
| `archive`: `mutate.go` | 74.2% | 88.7% | 42 | 0 |
| `archive`: `walk.go`, `capture.go` | 63.7% | 92.8% | 20 | 0 |
| `archive`: `diff.go` | 70.4% | 93.9% | 13 | 0 |
| `archive`: `ops.go`, `dict.go` | 63.1% | 94.2% | 22 | 0 |
| `archive`: `plan.go`, `dedup.go` | 59.2% | 96.7% | 4 | 0 |
| `archive`: the small files | 79.2% | 98.6% | 1 | 0 |
| `fsutil` | 67.3% | 84.1% | 7 | 0 |
| `meta` | 51.0% | 93.0% | 10 | 0 |
| `codec` | 64.7% | 88.1% | 36 | 0 |
| `cli`, with the operational tests | 67.9% | 96.1% | 31 | 0 |

The raw score counts an accepted mutant as a survivor. `make mutate` does
not count it, and gives 100% for each row. Part of the increase
in `format` comes from the change to the tool for case expressions: it tests
63 mutants that it showed as not covered before. The increase in `pipeline`
comes from the fault tests of step 3.

In `archive`, the work covers `writer.go`, `reader.go` and `fs.go`. The
first run found 77.4%, and the fault tests alone 55.4%. The survivors
showed these gaps, which are now closed:

- The index validator did not check `enc` as format.md §8.3 gives it: a
  salt of 16 bytes, and no `enc` on a member that is not `reg`. It does
  now. The writer also put an `enc` on an empty file, which has no blob.
  As for `off`, the writer and compact no longer write it, and a reader
  accepts it.
- The test of the pool of decoders had two kinds of zstd with different
  chunk sizes, so a key without the dictionary passed. Now only the
  dictionary tells them apart.
- `validateMemberRanges` is one range check in `uint64`, with no sum that
  can wrap, and a test of each bound.
- No test gave the reader a live count that does not match, a trailer
  outside the body, an index of more than 1 GiB, an index that does not
  decode (the reader then crashed), KDF parameters that the machine cannot
  afford, a damaged dictionary, or a member sealed in a plain archive.
  `reader_test.go` gives each.
- No test refused a planted link through `-f`, because only root can make
  a link of another user. A test now replaces the rule
  (`mayFollowLink`). `writer_test.go` also tests bad options to `Create`,
  a payload that writes too little, `Close` twice, and an append that
  writes nothing, which must keep the time of the file.

Of the 31 accepted mutants, 14 are checks of the reader that the index
validator makes first, and 3 are errors of `crypto/rand.Read`, which ends
the program instead.

In `extract.go`, most survivors were errors of the destination that no
test could make, so the fault test of step 3 came first (above). Then
tests for the parts that no fault reaches: the owner, the access time, the
notices for extended attributes that were not restored, directories
finished deepest first, a name of 250 bytes, files with holes in chunks
that do not fall on their segments, extraction to stdout, and the bound on
workers. The index checks do not check paths (doc/format.md 8.6), so a test
gives a directory, a link and a hardlink a path that is not in stored form.
Of the 27 accepted mutants, 5 need root, 2 run on another platform, and
the others change only the speed, or cannot happen after the index checks.

In `mutate.go`, the tests now give: the tombstones that compact keeps,
repair with windows as small as the magic of a trailer (so that a trailer
falls across two of them), an archive with no complete generation, the
checks of a change of passphrase, the choices of a recompress, and the
counts and the notices of verify across several batches. Fault cases for
an append, a compact and a recompress with a dictionary came with them.
They found the repair fault of step 3, and one more: the meter of a
recompress counted the content of the members that share it, which a
recompress does not decode, so it never reached its total. Of the 42
accepted mutants, most change only the batches or the number of workers,
or cannot happen after the index checks.

The NetBSD job of CI found a race in a recompress after these tests. Each
member is decoded by a goroutine into a pipe, which the pipeline reads.
When the pipeline failed, `recompressOne` returned and the caller closed
the reader, but the goroutine could still read the old archive. It then
read a file that was closed, and the program stopped with a panic. Now
`recompressOne` waits until the goroutine ends.
`TestRecompressOneWaitsForTheDecoder` holds the read of the goroutine,
and shows that `recompressOne` does not return before it.

In `walk.go` and `capture.go`, the fault test of the source came first
(step 3), and found three faults of the walk. Then tests for what no
fault reaches: each kind of file, a device, the requested paths `.` and
`..`, an absolute path with `-C`, a loop under `-h` named as a loop, the
limits of an extended attribute, a file that became a pipe, which the open
must refuse and not wait on, and `-u` with a file with holes, a link to
another target and a change of type. A test of finding 11 shows that a
link is read through the directory that the walk holds: read by its path,
it stored the link of the directory that took its place.

In `diff.go`, the fault test of the source covers `--diff` too (step 3).
The tests that came after give: a refused path, a root under a link that
leads out of the base, the order of the differences of one path, a change
of type, devices, owners, extended attributes against ACLs, a hardlink
whose target is a tombstone, files that do not open, and patterns with
`--strip-components`. Two live members with one path, from a forged
index, are compared in index order, as extraction writes them.

In `ops.go`, most of the mutants that survived were in helpers that only
the command line uses, such as the descriptions of a listing. They have
tests of their own now. The measurement of `train=auto` in `dict.go` is
now made of parts that a test can reach: the samples held out, the
candidate sizes, the net gain, and the order in which the candidates run.
Tests replace the trainer, the encoder of the measurement and the source
of dictionary ids, and make each one fail. The other tests give: the
budget of samples, the samples of a tree and of a recompression, a
dictionary of exactly the 1 MiB limit, and each check of a dictionary
that is read.

The dry runs of `plan.go` were tested by a comparison with their real
runs, which reached only the paths that both write. Tests now give their
refusals, their counts and sizes, `-O`, the current directory, devices,
files that `-k` keeps, and failures with and without `--keep-going`. In
`dedup.go`, the table of owners has tests of its own: which members own
content, the key of a file with many data segments, an owner that this
run wrote, and an old owner that fails its check.

The small files of `archive` are `strip.go`, `progress.go`, the locks,
the memory of the machine, the sync of a directory, and the seams `src.go`
and `dest.go`. The fault tests replace the seams, so a test now opens a
path that is not there through each seam on the disk: each gives the
error, and no file with it. The amount of memory is read by `memTotal`,
which a test gives lines of `/proc/meminfo` that are not usual. A lock
that fails for another reason than a lock that is held, and a collision
of a directory with a file after `--strip-components`, have tests too.

With this, each file of `archive` has no unexplained survivor.

In `fsutil`, five survivors were in `SafeJoin`, which nothing called:
extraction checks each path with `IsStoredPath`, and writes through
`os.Root`. `SafeJoin` is gone, and its hostile paths are now a test of
`IsStoredPath`. The first score counts its mutants, and the score now
does not. New tests give: a pattern with the characters of a glob, which
matches its own name; a pattern with a "/", which takes what is below it;
the path "//"; and an expression of `-R` that compiles alone but not in
the group that anchors it, at the limit of nesting.

In `meta`, two tests skipped where a fault made them pass. The test of
holes skipped when `DataSegments` called a file dense, so a fault that
lost the holes made it skip. Now it skips only when `SEEK_HOLE` itself
finds no hole. The test of names skipped when `UserName` gave no name.
Now a test takes the names from the system database of Go. A seam for
`lseek` gives the answers that a file system gives rarely: an error of
each call, data in all of the file, data past its size, and a hole past
its end. Other tests give: the escapes of `Mknod` and `Lchown` refused by
the check of the name, not by a lack of privilege; a device as root, of
each type, with its permissions and numbers; `O_NOFOLLOW`; an attribute
that grew between its size and its read; the errors of the attributes;
and ids 0, which are ids and not "no id".
The test of a device as root found a fault of `x/sys` on NetBSD, which
made each device node 0:0 (design.md §15.1).

In `codec`, the suite that runs for each codec did not reach the functions
that take a codec by name, which `cli` and `archive` call. Tests now give
their refusals of a name and of parameters, the window or dictionary that
the parameters ask for against the chunk, the dictionary of each preset of
xz, the estimates of memory for each speed of zstd, and the limits of
`train` and of a size. A decode appends to a destination that has no room,
little room, or room only with its prefix. A test makes a block of s2 that
has the right length and the wrong content. Of the 36 accepted mutants,
most are errors that cannot happen, such as a write to a `bytes.Buffer`,
or checks that the next check covers. One is too costly: a zstd window
larger than the chunk changes only the memory of the library.

In `cli`, the operational tests count: they run the binary, and with the
change to the tool above, the binary has the mutant. The first score, with
the tests of the package alone, was 67.9%. The operational tests raised it
to 77.2%, and the mutants that no test covered went from 95 to 18. The
tests that came after give: the refusals of each operation, `-T` from a
file and from the standard input, the long listing of a device, of a
shared member and of a deleted owner, the alignment of `-vv`, the rows of
`--info`, the messages of `--compact`, `--verify --quick` and `--repair`,
the dry runs, the search for the configuration file, the edges of the
escapes of a name, of a size and of the meter, and the owner of a
configuration file. A test on Linux opens a pseudo-terminal, and types
the passphrase: once, twice, two that do not match, and an empty one. Two
functions that nothing called are gone: `CompressSpec.IsNone` and
`passphraseSource.describe`.

With this, each package has no unexplained survivor.

**Step 2. A second reader, from `doc/format.md` only.** An independent
program reads an archive with the rules of `doc/format.md` and no code of
eictar. On the golden archives and on the archives of the stress tester, it
must give the same members and the same bytes as eictar. Thus the
specification is complete, the writer obeys it, and a user has a way to
read an archive that does not depend on eictar.

*Done.* `tools/ectread` is the second reader. It was written from
`doc/format.md` alone, and it imports no package of eictar: a test checks
this. It has its own CBOR decoder. It uses the same libraries as eictar for
zstd, S2, LZMA2, BLAKE3, Argon2id and XChaCha20-Poly1305. Thus a fault in
one of these libraries is common to the two readers. `make ectread` builds
`.build/ectread`, which lists an archive as lines of JSON (`-t`), reads
and checks each member (`-c`), or extracts it (`-x`).

These tests compare the second reader with eictar:

- `TestSecondReaderGoldens` and `TestSecondReaderCodecs` (operational) use
  the golden archives, and archives of each codec, plain and encrypted,
  with and without a sealed index. The archives have three generations, a
  dictionary, shared content, a sparse file, a pipe, and a hardlink whose
  target is a tombstone. A check makes sure that each archive has these.
  The fields of `-t --json` must be those that the reader decodes, and
  the tree that eictar extracts must hold the bytes that the reader
  decodes. Package `tools/ectread/compare` makes the two comparisons.
- The stress tester makes the same comparison after each step, and
  compares the extraction of the reader with its model. On a damaged copy,
  the reader must refuse what eictar refuses, and read what eictar reads
  (§4). After the fix below, a run of 10 minutes compared 2,469 states
  and 375 damaged copies, with no difference.
- `FuzzArchive` (step 4) runs the second reader on each changed golden
  archive. When eictar extracts the archive, the reader must read it with
  the same content. When eictar refuses it, the reader must refuse it too.
  A run of 3 minutes, on 541,000 archives, found no difference.
- The unit tests of the reader break each rule of `doc/format.md` §8.4 in
  the index of a golden archive. The reader must refuse each one.

The second reader found three gaps in the specification, one fault in the
reader of eictar, and one fault in the writer:

- format.md §8.3 said that a member that is not `reg` has no `off`. But eictar 1.1.0
  and earlier wrote an `off` on each member with no blob, of each type, as
  the golden archives show. The rule for the old writers now says so.
- format.md §8.1 said that the map keys are "sorted bytewise", and not of what. The
  order is that of the encoded keys, so a shorter key comes first. No
  reader checks it.
- After a compact of an archive whose members were all deleted, the index
  held `members` as null, and format.md §8.2 asks for an array. The stress tester
  found it. The writer now writes an empty array
  (`TestIndexNoMembersIsAnArray`). A reader accepts null, because eictar
  1.1.1 and earlier wrote it.
- format.md §6 gave no bound on the window of a zstd frame. eictar refused
  a window larger than the chunk size and 1 MiB, and the second reader
  took any window. Thus a frame that asks for 24 MiB, in a chunk of a few
  bytes, was damage to eictar and correct to the reader. `FuzzArchive`
  found it in the second run of the gate (step 6). format.md now gives
  eictar's bound, and the reader refuses a larger window. A test makes
  sure that eictar's writer never asks for more.
- eictar took a map key for a field of another case: `salT` for `salt` in
  the crypto header, `Path` for `path` in the index. The CBOR library does
  this by default. format.md §8.3 says that a reader ignores a key that it
  does not know, so the second reader found no salt and refused the
  archive, but eictar read it. `FuzzArchive` found it after the gate, in a
  run of 5 minutes. eictar now matches a key only by its exact bytes
  (`TestKeysMatchExactly`), and format.md §8.1 says so.

**Step 3. Faults of the disk and of the machine.** A layer under the writer
makes a write, an `fsync` or a rename fail, or makes a write short. A
power-loss mode records the writes, and drops or reorders the writes that
were not synced. After each fault, the archive must open as the old
generation or as the new one, or `--repair` must give back one of them. The
stress tester injects these faults at random.

*Part 1, faults that the program sees, is done:*

- In `archive`, each operation on an archive file and on its directory goes
  through a `fileSystem` (`fs.go`). In production, it is the operating
  system. `TestFaultsLeaveTheOldOrTheNewArchive` makes each of these
  operations fail in turn. It does this for create, create over an
  archive, append, delete, compact, recompress, repair and a change of
  passphrase, and for a create, an append, a compact and a recompress with
  a dictionary, plain and encrypted. A write that fails writes half
  of its bytes and gives `ENOSPC`. Each other operation gives `EIO`. After
  each fault, these rules apply:
  - The archive holds its old state or its new state. Only a fault in the
    truncate that undoes an append can make a repair necessary.
  - A run that reports success made the new state.
  - A run that reports success had no fault. There are two exceptions: a
    `chown`, which a user that is not root cannot always do, and a `close`
    of a file that the run did not write.
  - The error is the fault itself: an I/O error, not damage.
  - No file stays open, and no temporary file stays behind.

  `TestReadFaultsAreNeverSilent` does the same for extract and verify.
  Three faults put into the writer on purpose were each found. The rule
  on success came after a mutation run (below). It found two errors that
  the program ignored, and both are now fixed:
  - `Writer.SameFile` did a `stat` of the archive for each file of the
    walk, and gave "not the same file" when the `stat` failed. If the
    archive was inside a path to archive, it could then go into itself.
    The writer now does one `stat` when the archive opens, and a failure
    stops the run.
  - Repair ignored the error of its last `close`. After the `fsync`, this
    error can still report a lost write, on NFS for example.

  The rule that the error is the fault found one more: a read that failed
  while repair loaded a generation counted as damage. Repair then said
  that the archive had no complete generation (exit 3), when the disk had
  failed (exit 4). Now only damage, or a version that this build does not
  read, rejects a generation. The second matters for an archive of
  archives stored without compression: it holds the trailers of its
  members, which a later version can have made.

  Under `-race`, each run of the dictionary case trains a
  dictionary, which is slow. Thus, under `-race`, that case tests one
  fault in seven. The runs without `-race` (`make skips`,
  `make check-norace`) test each fault.
- In `pipeline`, each spill file comes from `newSpillFile`.
  `TestPipelineFaults` makes each operation on a spill file fail in turn,
  and each call to the encoder, to `NewSealer` and to `Emit`. It does this
  with a small budget and with a large one, and with a disk that stays
  full. It found two faults, which are now fixed (design.md §8), each with a test
  that fails without the fix:
  - When the encoder failed on a chunk that was not the last to return,
    the chunks after it waited for it for ever. The member never became
    complete, so the build left it out with no error, and its spill file
    and its budget stayed held. No codec of eictar gives such an error
    now: zstd and s2 give none, and deflate and xz fail on every chunk or
    on none.
  - After the build stopped, a member that the reader read at that time
    could still submit its chunks, because `select` chooses at random. Its
    `AddFile` then gave no error, and it was emitted after the failure.
    `Finish` gave the error, so no archive was wrong.
- In extraction, each operation on the destination goes through a
  `destDir` (`dest.go`): in production an `os.Root`, so that no name leads
  out of the destination. The calls of `meta` on a descriptor (a pipe, a
  device, the times of a link, an extended attribute) go through it too.
  `TestExtractFaultsAreNeverSilent` makes each of about 100 operations fail
  in turn: into an empty directory, over the tree, and with
  `--keep-going`. These rules apply:
  - An extraction that reports success, with no failed member, had no
    fault, apart from the close of a handle that wrote nothing.
  - The error is the fault itself: an I/O error, not damage, and not an
    unsafe path.
  - No directory or file stays open, and no temporary file stays behind.

  It found one fault, which is now fixed: before a link, a pipe or a
  hardlink replaced a node, a failed `lstat` counted as "nothing there".
  With the rule on the error, it also finds a fault that shows only later,
  as a link that was not made and then not found.
- The walk of a create, an append, a `--diff` and the training of a
  dictionary goes through a `srcDir` (`src.go`): in production an
  `os.Root`, so that each entry is found through the directory that holds
  it (doc/Security_Audit.md, finding 11). The reads of each file, of its
  holes and of its extended attributes go through it too.
  `TestCreateFaultsAreNeverSilent` makes each operation fail in turn, for a
  create, with `--keep-going`, `-h` and `--one-file-system`, for an
  append, with `--keep-going` and with `-u` by digest, and for a `--diff`,
  with and without `--keep-going`. The rules are those of extraction, and
  one more: without `--keep-going`, a fault stops the run with its error. A
  `--diff` that finds a difference has not failed, so a fault must not
  show as one. The test found four faults, which are now fixed:
  - The `stat` that gives `--one-file-system` its device ignored a
    failure. The device was then 0, each directory was on another file
    system, and the archive was empty, with no error. Now the walk makes
    the `stat` only for `--one-file-system`, and a failure stops it.
  - A requested path whose parent did not open was walked by its path,
    for any error. That is for a parent that the user cannot list: now
    only a permission error does it.
  - Each error that opened a directory of the walk was "changed after the
    walk found it". A fault of the disk is now itself, and only the errors
    of a change (gone, not a directory, a link) say that.
  - `--diff` did not check a hardlink whose target did not lstat, for
    any error, and found no difference. Only a target that is gone is not
    checked now: the walk reports it as missing. The first form of this
    fix counted the failure and gave no error, because the check of
    hardlinks comes after the run reads its first error. The rule on
    `--keep-going` found that before the fix was committed.

*Part 2, power loss, is done.* `crash_test.go` puts a model of the disk
behind the same `fileSystem`. The operations reach the disk as in
production. Beside them, the model keeps the content of each file at its
last `fsync`, each write since then, and the names of the directory at
its last directory `fsync`. After each change, it records what the path of
the archive can hold if the power fails then:

- the names of the last directory `fsync`, or the current names;
- for the file at that name: its content at its last `fsync`; its current
  content; the content at its last `fsync` with half of what came after
  (a torn write); or its current content with one write since the last
  `fsync` lost (writes that reach the disk out of order).

`TestPowerLossLeavesTheOldOrTheNewArchive` runs the operations of part 1,
and checks each state that the model recorded. These rules apply:

- The archive holds its old state or its new state.
- An operation that writes in place (append, delete, repair) can need
  `--repair` to give one of them back. An operation that commits with a
  rename (create, compact, recompress, a change of passphrase) must never
  need it.
- When the operation has reported success, the state that the `fsync`
  calls put on the disk is the new one.

No operation broke a rule. Five faults put in on purpose were each found:
no `fsync` of a new archive before its rename, no `fsync` of the directory
after the rename, no `fsync` of a compacted archive, no `fsync` of the
index before the trailer, and no `fsync` after repair cuts the file. The
fourth one needs the model of lost writes. The index and the trailer
reach the disk, but a write of a blob before them does not, so the
archive opens as the new generation, and its members fail their digest.

The model takes a file system that keeps a rename in order with the other
changes to the directory, and that does not change bytes that no write
touched. It does not model a disk that lies about `fsync`.

*Part 3, faults in the stress tester, is done.* A file of `archive` that is
built only with `-tags faultinject` (`faultinject.go`) puts a layer on the
same `fileSystem`. `EICTAR_FAULT=KIND:N` makes the Nth operation of a kind
fail, and a line on stderr says that it happened. A release binary does not
have the file. `make stress-build` builds `.build/eictar-faults` with it, and
the stress tester runs a change of the archive with it at random (§4).
Thus the faults meet the random trees, codecs, dictionaries and histories
of the stress tester, which the unit tests of part 1 do not. A run of five
minutes made 167 changes with a fault, and in 33 of them the fault
happened and the command failed. Each one exited with 4, and left the old
state or the new one, with no file beside the archive. No rule broke. `make
vet` checks the file with the tag, so that it cannot stop compiling.

With this, step 3 is done.

**Step 4. More fuzzing.** A fuzz target opens, lists, verifies and extracts
changed copies of the golden archives into a temporary root. Each run must
end with exit 3, or with the exact content, and never with a panic or a
write outside the root. More targets cover the chunk opener, the
configuration parser, the compression spec, and the pattern rules against a
simple reference matcher. Before a release, each target runs for hours, and
the corpus is kept.

*Done.* `make fuzz` runs twelve targets (`FUZZ_TARGETS`). The six new ones:

- `FuzzArchive` (`archive`) changes the bytes of a golden archive, then
  lists, verifies and extracts it into a temporary root. Each operation
  ends with an error that gives exit 3, or with success. A successful
  extraction gives exactly the content of a generation of a golden
  archive: a cut at the end of a generation makes an older archive that
  is valid. The target finds the content of each such cut before it
  starts. Verify and extraction agree. Nothing is written in the
  temporary directory outside the root. The target takes bytes alone,
  because the fuzzer changes one golden archive into another, and the
  header of a plain archive is not authenticated. Its first run found
  that fault in the target, not in eictar. A changed crypto header can
  ask for 4 GiB for the key derivation, so the target lets the machine
  have 32 MiB (`kdfMemory`). The derivation is then refused above 16 MiB.
- `FuzzChunkOpen` and `FuzzIndexAndDictOpen` (`crypt`): a sealed chunk,
  index or dictionary opens only if the sealer makes the same bytes from
  its plaintext, in its place. It does not open at another index, with the
  other final flag, in another member, or for another generation or id.
- `FuzzMatch` (`fsutil`) compares `Match` with a matcher that follows the
  four rules of design.md §10.11 and has a glob of its own. The patterns are of `a`,
  `b`, `*`, `?` and `/`. With one rule taken out of `Match`, it finds a
  difference in less than a second.
- `FuzzCompressSpec` (`cli`): a spec that parses has a name, and no empty
  key or value, and its `String` parses back to the same spec.
- `FuzzConfigFile` (`cli`): any content of a configuration file gives a
  usage error, an error of the read for a line that is too long, or
  settings that `--show-config` shows.

In their first runs, `FuzzArchive` ran 5 minutes (about one million
inputs), and `FuzzMatch` one minute (27 million). No fault of eictar came
out. Go keeps the corpus in `.gobuildcache/fuzz`. The runs of hours before
a release are for step 6.

**Step 5. Models of the protocols.** TLA+ models check three protocols, where
faults of order and of timing hide:

- the commit of a generation, and `--repair` (design.md §9.1, §9.5)
- the lock, and the check that the path still names the locked file (design.md §9.6)
- the rules of the memory budget against a deadlock (design.md §8.1)

The two hangs that the tests found were both in the memory budget.

*Done.* `make tla` checks four models in `spec/` with TLC, the model checker
of TLA+. TLC needs Java and `tla2tools.jar` (from the releases of
`github.com/tlaplus/tlaplus`) in the root of the project. Git does not keep
the jar, and the CI does not run the models. Each model has configurations
that take out one guarantee of the program, and TLC must find the fault in
each. Thus a model that cannot see a fault makes `make tla` fail.

- `Commit.tla`: an append, an update or a delete (design.md §9.1), and the cut-back
  after an error. The disk keeps each write and truncate in a cache until
  an `fsync`. At a power failure, any subset of the cached operations is on
  the disk, in order, and a write can be torn. In each state, after a power
  failure, the archive gives the old generation or the new one, at worst
  after `--repair`. A success is durable. An error leaves the old archive
  when the truncate worked. TLC finds the fault when the `fsync` before the
  trailer, after the trailer, or after the cut-back is gone.
- `Replace.tla`: a compact, a change of passphrase and a create, which
  rename a temporary file over the path (design.md §9.3, §9.7). The path gives the
  old archive or the complete new one, and a success is durable. Without
  the `fsync` of the new file, the path can name an incomplete archive.
  Without the `fsync` of the directory, a success is not durable. That is
  the case on Windows (design.md §15.1).
- `Writers.tla`: appends, compacts and creates at the same time, with the
  lock and the check of the path (design.md §9.6). No append that reported success
  is lost, unless a create replaced the archive after it. TLC finds a lost
  append without the check of the path, and when a compact reads its
  archive before it takes the lock, a fault that the code had before.
- `Budget.tla`: the memory budget of a create (design.md §8.1). No state stops for
  ever, each member reaches the archive, the budget stays within its
  limit, and all of it comes back. TLC finds a deadlock without the spill
  before the wait (the hang that M8 fixed), with a spool that waits for
  budget, and with a budget of one chunk.

The models found one fault in the program. A create that found no archive
at the path held no lock. A second create could then make an archive
there, and an append could start on it. The first create renamed its own
archive over it, and the append, which reported success, was lost. Now the
rename of such a create fails when a file is at the path, and the create
stops with exit 4 (design.md §9.6). `TestCreateDoesNotReplaceAnArchiveThatAppeared`
fails without the fix.

The models also showed that design.md §9.1 listed one `fsync` more than the code
makes: the blobs and the index have one `fsync` together. The text now
follows the code.

The models have limits. A model is not the code, and only the tests check
that the code does what its model does. The models are small: three
members of three chunks, up to three workers, and up to six writers. They
take a rename to be atomic, and a disk that does not lie about `fsync`, as
the test of power loss does (step 3).

**Step 6. The release gate.** Before a tag, these must pass:

- `make check` on each platform, as CI does
- a run of the stress tester of at least 8 hours
- each fuzz target for at least one hour
- `make mutate` on each package, with no survivor that is not explained
- `govulncheck` on the modules and the standard library
- the TLA+ models

*Done.* `make gate` runs each step that one machine can run, in this
order: `make check`, `make tla`, `make vuln`, `make mutate` on each package,
`make fuzz` with one hour for each target, and `make stress` for 8 hours.
The CI workflow gives `make check` on the other platforms (design.md §12.3). The
quick steps come first, so that a fault in them stops the gate before the
long steps start. The gate stops at the first step that fails, because a
fix makes a new commit, and the gate must run again on that commit.

The gate runs on a git worktree of the commit, in `.tmp/gate/`. Thus the
result belongs to that commit, and not to the changes in the working
tree, and work can continue while the gate runs. Also, a mutant can write
files in the directory of its package, where `go test` runs it. In the
gate, these files stay in the worktree, which the gate removes. The worktree uses the
caches of the project, so the fuzz corpus grows from one gate to the next.
The gate writes the output of each step to a log in `.build/gate/SHA/`,
and a record with the commit, the toolchain, and the result and time of
each step. The last line of the record is `PASS` only when every step ran
and passed. The release steps of design.md §12.3 ask for this line. When a step
fails, the worktree stays for the examination. For example, it holds the
input of a fuzz target that failed, in `testdata/fuzz`.

`make vuln` runs `govulncheck` (`golang.org/x/vuln`, at a fixed version).
It finds only the vulnerabilities that the code calls, so a vulnerability
in a function that eictar does not use does not stop a release. The scan
uses the toolchain that builds, because the standard library is part of
the binary. The release workflow runs `make vuln` too, with the toolchain
that builds the release binaries.

The scan knows only the entries of the Go vulnerability database. An
advisory that a module publishes on GitHub can come days before its entry,
or with no entry. GHSA-fpmh-frq8-7rj8, a panic of the zstd decoder of
`klauspost/compress` v1.20.1 and earlier on a crafted frame, had no entry
when the gate passed `make vuln`. Thus a release also needs a read of the
advisories and the release notes of each module (design.md §12.3, step 1).

The first run of the gate found a vulnerability. GO-2026-6604 lets
`os.Root.MkdirAll` follow a junction out of the root on Windows. An
extraction uses `os.Root` to keep each member in the destination (design.md §7.6).
Go 1.27.2 fixes it. The toolchain of the development machine was 1.27.1,
so the gate stopped at `make vuln`. The release workflow takes the newest
patch release of the version in `go.mod` (`check-latest` of `setup-go`),
so a release built after Go 1.27.2 has the fix. Without `check-latest`,
an older 1.27.x in the cache of the runner satisfies `go.mod`.

The first run also found a mutant in `pipeline` that the tests found only
by chance of timing. A member is complete when the reader drops its claim
and every chunk is in the spool. Either one can come last, but in a build
the last chunk usually comes after the reader. Thus a fault in the check
of the reader showed in the runs of step 1, and not in this run.
`TestMemberCompletesInEitherOrder` now gives both orders.

In `archive`, the run found two more gaps:

- The rename of step 5, which does not replace a file, had one survivor
  and four mutants that no test ran. A check after `link(2)` did the same
  as the check that follows it, so it is gone. The path for a file system
  with no hard links had no test. `TestRenameNew` now gives both kinds of
  file system: the name is free, the name is in use, and the check fails.
- Two entries of the accepted list in `capture.go` said that a file with
  one name never has the identity of another file. That is false under
  `-h`: a symbolic link and its target are one file with one name. A test
  of the dry run from step 1 finds both mutants, so the entries are gone.
  Thus the rule that an entry must stay true worked.

The step took 3 hours and 21 minutes, of which `archive` took 3 hours.

The work on the gate also found that the operational tests left the
binary that they built in `.tmp/`, which no one clears. Each mutant of
`cli` runs them, so the runs of step 1 left 2,700 binaries, or 23 GB. A
`TestMain` now removes the binary after the tests (`RemoveBinary`). A test
that stops at its time limit still leaves its binary. In the gate, the
worktree goes with it.

The second run of the gate, on 2026-10-17, passed `check`, `tla`, `vuln`
and `mutate` (3 hours and 35 minutes). Then `FuzzArchive` found a zstd
frame that eictar refused and the second reader read, after 52 minutes of
the fuzz step. The cause was a gap in `doc/format.md` (step 2). The input
is in `src/internal/archive/testdata/fuzz/FuzzArchive`, so each test run
tries it again.

A CI run on Linux stopped after 30 minutes in `TestPromptReadFails`, and
the next run passed. A goroutine dump showed the prompt in a loop of reads.
After a terminal hangs up, each read gives 0 bytes and no error, and
`term.ReadPassword` reads again for ever. The test closes the terminal
while the prompt waits, and the fault showed only when the close came
between the set of the terminal and the first read. A loop of 3,000 runs
under `-race` stopped in the same way in 4 minutes.
`TestPromptAfterAHangup` now gives the hangup before the read every time,
and eictar reads the line itself (design.md §10.3). The mutation step
found three survivors in the new code: the settings of the terminal, and
an error of each call that reads or sets them. `TestReadPasswordSetsTheTerminal`
now tests them. A terminal that cannot turn off the echo stops the prompt
before it reads.

The third run of the gate, with `klauspost/compress` v1.20.2, stopped in
`mutate` after 10 minutes. The `recover` in the training of a dictionary
had a survivor. The trainer of v1.20.1 panicked on too little input, and
`TestTrainingFailsCleanly` gave that input. The trainer of v1.20.2 returns
an error for it, so no test made a panic. The `recover` stays, for a panic
that is not known yet. `TestTrainerPanicIsAnError` replaces the trainer
with one that panics. Thus an update of a module can take away what a test
tests, and the mutation step finds it.

| Step | Status |
|---|---|
| 1. Strength of the tests | done: each package has no survivor that is not explained |
| 2. Second reader | done: `tools/ectread`, with no difference from eictar |
| 3. Faults of the disk and the machine | done: faults that the program sees, power loss, and faults in the stress tester |
| 4. More fuzzing | done: twelve targets |
| 5. Models of the protocols | done: four models; they found one fault |
| 6. Release gate | done: `make gate` |

