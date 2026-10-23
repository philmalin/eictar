# eictar — History

Date: 2026-10-15
Applies to: v1 (format version 1.0)

This document gives the milestones that built eictar, and the changes of
each release. `design.md` describes the format and the program, and
`testing.md` describes the tests. This document was §16 of `design.md`
until 2026-10-15.

## Contents

[1. Milestones](#1-milestones) ·
[2. Releases](#2-releases)

## 1. Milestones

Each milestone includes its unit tests (testing.md §1). From M2, each milestone also
extends the operational tests (testing.md §2). "Complete" means that the tests exist
and pass, not that the feature ran once by hand.

1. **M1 — Skeleton** *(complete)*: the module and the option parser. The
   `format` package, with the header, the trailer, the index and their fuzz
   tests. The `testutil` fixtures and the tree comparison. An operation that
   is not built yet exits with 70 and names its milestone. Every operation is
   built now, and the rule stays for an option that is not (design.md §10.6).
2. **M2 — Plaintext core** *(complete)*: create, list, extract and
   `--list-codecs`, with the codecs `none` and `zstd`. It supports regular
   files, directories and **symbolic links**. Links, `-h` and the `os.Root`
   protection came early from M5. The program refuses a type that it cannot
   store (a device, a socket, a named pipe). It never skips such a file
   without a message. `--keep-going` changes the refusal to a warning and
   exit 1.
3. **M3 — Concurrency** *(complete)*: `src/internal/pipeline` (the chunk pool,
   the spools, the memory budget with `TryAcquire`), parallel extraction,
   `-j`, `--memory-limit` and `--spill-threshold`. Tests with 1 to 64 workers
   pass under `-race`. The measured speedup is 5.5 times on eight cores
   (design.md §8.2). The first version deadlocked (design.md §8.1). Its
   workers also shared an encoder with one state, so `-j 8` was no faster
   than `-j 1` (design.md §8.2).
4. **M4 — Encryption** *(complete, reviewed)*: `src/internal/crypt` holds
   Argon2id, the HKDF key schedule, XChaCha20-Poly1305 for chunks, and the
   sealed and authenticated index. The milestone also added `--encrypt`,
   `--encrypt-index`, the passphrase sources, the KDF limits and the memory
   check of design.md §A.3. Fixed vectors test the key schedule. Tamper tests cover
   content, metadata, truncation, chunk movement and downgrade.
5. **M5 — Metadata** *(complete)*: `src/internal/meta`. Xattrs and ACLs,
   hardlinks, pipes, devices, holes, ownership by name and number, special
   mode bits with `-p`, and link times with `utimensat`. Also `--exclude`,
   `-X`, `--one-file-system`, and a long listing with owner and codec. A 4 GB
   disk image with two small data regions archives to 472 bytes and extracts
   with its holes. Symbolic links came early, in M2.
6. **M6 — Mutation** *(complete)*: append, update, delete, compact,
   `--verify`, `--info` and `--repair`, with `--on-conflict`, `--update-mode`
   and `--quick`. The milestone also added the crash-consistency tests and
   the golden files. The review changed the index nonce from the generation
   to a random value (design.md §6.3). It also corrected three faults:
   - a replace under `--keep-going` lost both copies of a path that failed
   - a hardlink pointed to a member that failed
   - `-u` stored the second name of a hardlink pair again in full

   A second code review corrected two more faults, each with a regression
   test:
   - a read error part way through a file crashed the program, because a
     worker wrote a chunk to a spool that was already closed
   - a failed create removed the archive that was already at the path (design.md §9)

   The review also changed the write sequence. The design put the new blobs
   on top of the old trailer, so a crash left nothing to recover. Now they
   go after it (design.md §9.1).

   The same review made each pattern of `-t`, `-x` and `--verify` match at
   least one member, as for `--delete` (exit 2). It also made the other
   links to a target that was not extracted link to the first copy (design.md §7.7). It
   removed dead code, and one copy of each chunk. design.md §15.2 lists the items that
   it left for later.
7. **M7 — Completion** *(complete)*: the configuration file and the
   environment variables (design.md §11), and the codecs gzip, flate, xz and s2
   (design.md §10.2). Also `--progress` (design.md §10.10), `--recompress` (design.md §9.3), and the
   advisory lock for writers (design.md §9.6). Also the man page (`doc/eictar.1`), the
   format reference (`doc/format.md`), and the benchmarks (design.md §8.4). Every
   option is built. The `Makefile` sets `GOCACHE`, so a build writes nothing
   outside the project (design.md §12).

   The work changed three points of the M6 design. The M6 design locked the
   new file of compact. Now a writer locks the archive, and then makes sure
   that the path still names the file that it locked (design.md §9.6). There is no bzip2 codec for
   decompression only (design.md §10.2). `--no-config` ignores the `EICTAR_*`
   variables too, not only the file (design.md §11).

   The work found and corrected these faults:
   - the xz reader took its dictionary size from the stream, so a crafted
     chunk was able to make it allocate 4 GiB (design.md §10.2)
   - the binary tree of the xz library takes hours on a chunk of zeroes
   - a lock on a file that a rename replaced let an append write to the old,
     unlinked file (design.md §9.6)
   - a variable named `EICTAR_*` for `--passphrase-env` was refused as an
     unknown setting (design.md §11.2)
   - each file took a new 4 MiB read buffer, and create was up to 7 times
     slower than necessary (design.md §8.4)
   - a gzip chunk carried a meaningless time
8. **M8 — Other UNIX-like platforms** *(complete)*: metadata on macOS,
   FreeBSD, NetBSD and OpenBSD, as design.md §15.1 describes. Open questions 4 and 5
   are decided (design.md §1.1, rows 8 and 9). The CI workflow in
   `.github/workflows/ci.yml` passes on all five platforms. The first runs
   found five faults that no run on Linux had shown:
   - a deadlock in the pipeline, on a CI runner with two CPUs (design.md §8.1)
   - `.tmp` is not in the repository, and `vet` and `fmt` did not create it
   - a configuration test used a worker count that is the default on a CI
     runner with two CPUs
   - the hole test expected the 4 KiB granularity of ext4, but ZFS reports
     128 KiB records
   - a recompress test expected holes on NetBSD and OpenBSD, which store
     files dense. Also, the NetBSD job used `sort -V`, which NetBSD does not
     have.
9. **M9 — Format revision** *(complete)*: a random data key that the
   passphrase wraps, `--change-passphrase` (design.md §9.7), and a keyed member digest
   in encrypted archives (design.md §6.2). Both change the format, so they come before a
   first release, with new test vectors and golden files. Before M9, the
   passphrase gave the master key directly, so a change of passphrase was not
   possible, and the header held the `check` value of M4 to find a wrong
   passphrase. The tag of the wrapped key took its place (design.md §6.2). The
   member digest was not keyed, so it showed if the archive held a file that
   an observer had (design.md §14.1). These are two of the items that the M6
   review left for later (design.md §15.2).
10. **M10 — Dictionaries** *(complete)*: `-Z zstd:train` trains a zstd
    dictionary in a pass before the compression. The archive stores it,
    sealed when the archive is encrypted (design.md §4.2, §5.1, §6.3). Codec
    keys take the form `k[=v]`, so `long` and `train` can stand alone
    (design.md §10.2). The dictionary adds index fields, so it comes before the first
    release, v1.0.0, with a new golden archive.
11. **M11 — Identical content** *(complete)*: a member whose content is
    already in the archive refers to the blob of that member, and stores
    nothing (design.md §4.3). A file with the size of a stored one is hashed before
    it is compressed. `--no-dedup` turns the rule off. It adds the member
    field `data`, so it comes before v1.0.0, with a new golden archive.

## 2. Releases

Between M9 and M10, the module path became `github.com/philmalin/eictar`.
The interface also got the `.ect` extension (design.md §10.12), and selection by
regular expression, `-R` and `--exclude-regex` (design.md §10.11). After M11, the
release workflow made the first release, v1.0.0 (design.md §12.3). The next release,
v1.0.1, made zstd level 12 the default (design.md §10.2), in place of 3, the
default of zstd. It also bounded the memory of the encoders, because the test
machines of FreeBSD and OpenBSD ran out of memory at level 12 (design.md
§8.2).

**v1.0.2 is a security release.** A review of v1.0.1 found eight problems
(`doc/Security_Audit.md`). Two were serious for a root user with an archive
from someone else: privileged xattrs, and a member `.`. The release fixes six,
each with a test (design.md §7.7, §9, §14), and documents the other two (design.md §14.1).

**v1.0.3** makes `--verify` parallel (design.md §9.4), and uses decoders again,
within a bound that a hostile index cannot raise (design.md §8.3; finding 10 of the
audit). The default of `-j` is three quarters of the CPUs (design.md §8). A name that
is an existing directory gets `.ect` even when it has a dot (design.md §10.12). A new
fuzz target covers a zstd dictionary from an archive.

**v1.0.4** comes from a review of the code after v1.0.3, and fixes these
faults:

- **Compact can lose an append.** Compact read the index before it took the
  lock. An append that committed between the two was not in the compacted
  archive, which replaced the file. Compact now takes the lock first, as
  design.md §9.6 requires.
- **`--keep-going` does not cover the walk.** A directory that could not be
  read, or a file that went away during the walk, stopped a create or an
  append with no archive. Under `--keep-going` it is now a failed member:
  the directory is archived empty (left out on macOS, which cannot read its
  extended attributes), and the run ends with exit 1 (design.md §10.4).
- **`--keep-going` does not cover the final pass of extraction.** The first
  directory whose metadata failed stopped the run, and the directories after
  it kept their private mode of 0700. The pass now goes on (design.md §8.3).

It also makes extraction of small files about 3 times faster, with a root
for each directory and batches of files, and it copies the list of members
less often (design.md §8.3). Parallel `--verify` no longer copies every member. A
reader now refuses a flag or a reserved byte that it does not know, as a
newer version of the format (design.md §3.1). Thus a later version can mark a change
that this one must not ignore. The format is still 1.0: v1.0.4 reads every
earlier archive, and earlier versions read what it writes.

The tag of v1.0.3 left out the tests of its pool of decoders and the
results of its fuzz run (`doc/Security_Audit.md` §6). v1.0.4 has them.

**v1.0.5** updates `klauspost/compress` to v1.20.1, `ulikunitz/xz` to
v0.5.17 and `klauspost/cpuid` to v2.4.0. The updates change decoders that
read untrusted archives: the zstd and huff0 decoders, and an xz reader that
returns no data and no error is no longer a failure. `make check` and a fuzz run of each target passed,
the ratios did not change, and the speed did not change by more than the
noise of the benchmarks (design.md §12.3). The program now warns when an xz preset
has a dictionary larger than the chunk size, as it does for a zstd window
(design.md §10.2). `THIRD_PARTY.md` lists the modules in the binary with their license
texts, and a release includes it. Dependabot proposes updates of the modules
and the actions each month (design.md §12.3).

**v1.0.6 is a security release**, and it adds two operations. A review of
the changes after v1.0.5 found two problems (`doc/Security_Audit.md` §7).
The release fixes both, each with a test:

- **The walk can leave the tree** (finding 11, medium). The walk examined a
  directory with `lstat`, and then opened it by its path. A user who can
  write in the tree can replace the directory with a link between the two
  steps. A root backup of that tree then stores files from outside it. The
  walk now holds each directory that it enters open, opens each entry
  through it, and makes sure that a directory it opens is the one that
  `lstat` found (design.md §14.5). The cost is about 30 ms on 20000 files, for
  `--diff` only (design.md §9.8).
- **A name can control the terminal** (finding 12, low). The program wrote
  member names to the terminal as they are. A crafted name can move the
  cursor, change the title, or hide text. On a terminal, the program now
  escapes control characters, invalid UTF-8, bidirectional controls and the
  backslash in a name. A message is always escaped (design.md §10.13). A listing that
  goes to a file or a pipe does not change.

The new operations:

- `--diff` compares an archive with the tree on disk (design.md §9.8). It reports the
  members that are not on disk, the paths on disk that are not in the
  archive, and each difference of type, content or metadata. It changes
  nothing, and it ends with exit 1 when there is a difference.
- `-n` (`--dry-run`) shows the paths that create, append, update, extract or
  delete would write or delete, with the same selection, and changes
  nothing (design.md §9.9). Use it to see what a pattern or a regular expression
  takes.

Other changes:

- `zstd:train` alone is now `train=auto`. The writer measures the best size
  of the dictionary on the files, and uses no dictionary when none helps
  (design.md §4.2). Before, `train` used a fixed 112 KiB, which made 9 of 29 test
  trees larger than no dictionary. `train=SIZE` still gives a fixed size.
- On a read, an `--exclude` glob with a `/` now takes the contents of a
  directory that it matches, as the walk does (design.md §10.11). Before, it took
  only the directory.
- `--diff` keeps the differences of a path whose extended attributes it
  cannot read. macOS refuses them for a file that the user cannot read
  (design.md §9.8).
- `-h` on an operation that does not walk is a usage error. Before, the
  program ignored it.

The format is still 1.0. v1.0.6 reads every earlier archive, and earlier
versions read what it writes. An archive made with `train=auto` holds an
ordinary dictionary, so v1.0.5 reads it too.

**v1.0.7 adds one option, and fixes two faults.**

The new option:

- `--strip-components N`, with `-x` and `--diff`, removes the first N
  components of each path (design.md §10.14). Patterns, `-R` and `--exclude` match
  the paths in the archive, before the strip. A member with N components
  or fewer is not extracted. When two members get one path, the later one
  in path order is extracted, with a warning, and the run ends with exit 1.
  Two directories with one path are not a collision. A path that is not
  safe is not stripped, so the extraction still refuses it. `--diff` with
  the option compares the tree that such an extraction writes. The option
  is refused with `-O`, and in a configuration file.

The fixes:

- `--diff` reported the directory of a member as a path that the archive
  lacks, when `-r a/b/c` had added the member by its own path, with no
  member for `a/b` (design.md §9.8).
- An encrypted archive whose crypto header gives less than 8 KiB of KDF
  memory for each thread now gives exit 3, for damage. Before, it gave
  exit 4, as for an internal error (design.md §6.2). The program refused the archive
  in both versions, and read no data from it.

Other changes:

- The stress tester has steps for `--diff`, `-n` and `--strip-components`.
  Its summary starts with PASS or FAIL, and gives each check with the
  number of times that it held, and the five slowest commands (testing.md §4).
  Runs of 1, 2 and 3 hours found the second fix above, and the cost that
  design.md §15.2 records.
- design.md §15.2 records why `zstd:train` is slow at level 10 and above on small
  files or small chunks, and a fix in the library that a prototype
  measured. The item waits for the library.
- A test of `--diff` no longer depends on the resolution of the file
  times. It failed now and then on OpenBSD.

The format is still 1.0. v1.0.7 reads every earlier archive, and earlier
versions read what it writes.

**v1.0.8 fixes one fault, and starts the work for Windows.**

The fix:

- A create could hang with no message when a member could not move to disk.
  When memory is full, the reader moves the member that it reads to a spill
  file, and then waits for memory. If the spill file could not be made, for
  example on a full disk, the member kept its memory, and the wait did not
  end. Now the member fails with the error of the spill (design.md §8).

Other changes:

- On Windows, the writer also removes the drive or the share from an
  absolute path. Thus the notice is now "removing leading '/', '..' or
  drive from member names" (design.md §7.3). On other platforms, only the text of
  the notice changes.
- Windows is not a supported platform yet, and the release has no Windows
  binary. The program now passes the tests there, and the CI workflow runs
  them. design.md §15.1 gives what the program does on Windows. The work found that
  the check against a file swapped in after the walk did nothing on Windows
  for a path named on the command line (`doc/Security_Audit.md`, finding 3).
  That fault was on Windows only.
- `make large` takes an archive past 4 GiB through each operation that reads
  or writes an offset or a length (testing.md §2).
- The stress tester checks the identity of hardlinks after each extraction.
  It gives a new entry another name when its name is taken. A 4-hour run
  failed on such a collision, and an 8-hour run passed after the fix
  (testing.md §4).
- `make crossvet` runs `vet` for each platform from one machine, and `make
  check` includes it. CI leaves it out, and uses the caches that `setup-go`
  saves (design.md §12, §15.1).

The format is still 1.0. v1.0.8 reads every earlier archive, and earlier
versions read what it writes.

**v1.1.0 makes Windows a supported platform, and fixes one fault on
OpenBSD.**

Windows:

- Windows is now a supported platform, on amd64 and arm64. The release has a
  `.zip` file with `eictar.exe` for each. It has no man page. The CI job for
  Windows now fails the workflow when a test fails (design.md §12, §15.1).
- On Windows, eictar records no owner, no mode and no extended attributes.
  It skips named pipes and device nodes on extraction, with a notice. It
  stores a file with holes dense. design.md §15.1 gives the other differences.
- The program reads the owner and the ACL of a configuration file and a
  passphrase file. It refuses a configuration file that an account other
  than you, SYSTEM or the Administrators group owns, or that the ACL lets
  such an account write. It warns about a passphrase file that such an
  account owns or can read (design.md §11, §15.1, `doc/Security_Audit.md`,
  finding 8). Before, the program did not do these checks on Windows.
- `GlobalMemoryStatusEx` gives the size of the RAM for the budget and for
  the check of the key derivation (design.md §8.1, §15.1).

The fix:

- On OpenBSD, the program did not get the size of the RAM. It asked for
  `hw.physmem64`, which `x/sys` does not know on OpenBSD. Thus the budget
  did not use a quarter of the RAM as its limit, and the check of the key
  derivation did nothing. Thus on a small machine, a key derivation that
  asked for more memory than the machine had got no refusal, and the kernel
  stopped the process with no message. The program now asks for `hw.physmem`, which `x/sys` maps to
  `HW_PHYSMEM64` (design.md §15.1). `TestTotalMemory` checks that each supported
  platform gives a size.

The format is still 1.0. v1.1.0 reads every earlier archive, and earlier
versions read what it writes.

**v1.1.1 fixes faults that a new plan of tests found (testing.md §5).** The plan
measures how strong the tests are, and makes the disk fail under each
operation. Each fix has a test that fails without it.

The fixes that change what an archive holds, or the result of a command:

- With `--one-file-system`, a `stat` that failed gave the device 0. Each
  directory was then on another file system, and the archive was empty,
  with no error. Now a failure stops the create.
- `--diff` did not check a hardlink whose target did not `lstat`, for any
  error, and found no difference. Now only a target that is gone is not
  checked, and the walk reports it as missing. The other errors are
  failures.
- Before a link, a pipe or a hardlink replaced a node on extraction, a
  failed `lstat` counted as "nothing there". Now it is an error.
- On NetBSD, each device node that `--preserve-devices` made was 0:0. A
  fault in `x/sys` put the device number where NetBSD has a padding
  argument. eictar now makes the system call itself (design.md §15.1).
- `--compact --recompress` could stop with a panic when the compression
  failed: the read of the old archive went on after the archive was
  closed. Now the operation waits for that read to stop.
- The writer did a `stat` of the archive for each file of the walk, and a
  failure gave "not the same file". An archive inside a path to archive
  could then go into itself. Now the writer does one `stat` when the
  archive opens, and a failure stops the run.

The fixes of messages and of exit codes:

- `--repair` ignored the error of its last `close`, which can report a
  lost write on NFS. Now it is an error.
- A read that failed while `--repair` loaded a generation counted as
  damage, and repair said that the archive had no complete generation
  (exit 3). Now it is an I/O error (exit 4).
- Each error that opened a directory of the walk said "changed after the
  walk found it". Now a fault of the disk shows as itself.
- A requested path whose parent did not open was walked by its path, for
  any error. Now only a permission error does that.
- The progress meter of `--compact --recompress` counted the content of
  the members that share it, which a recompress does not decode, so it
  never reached its total.
- On Windows, the check for a link that another user planted in the path
  of `-f` stopped at the volume, and checked nothing
  (`doc/Security_Audit.md`, finding 4).

Faults that no release showed, now fixed too:

- When an encoder failed on a chunk that was not the last to return, the
  member was left out with no error. No codec of eictar fails that way.
- After a create failed, a member could still be emitted. The run gave the
  error all the same, so no archive was wrong.

The format:

- The writer, compact and recompress do not write `off` on a member with
  no blob, as `doc/format.md` §8.3 says. A reader accepts it and ignores
  it, because 1.1.0 and earlier wrote it.
- The validator refuses more shapes of a hostile index: a chunk on a
  member that is not a file, and a chunk for an empty payload. No version
  of eictar wrote them.
- `doc/format.md` is now the specification of the format, and the tests
  check the key schedule against it.

The format is still 1.0. v1.1.1 reads every earlier archive, and earlier
versions read what it writes.

**v1.1.2 is a security release.** It is the first release that passed the
release gate (testing.md §5, step 6). The gate ran each check of the plan
on the code of the release, in 24 hours: 1 hour of fuzzing for each
target, and 8 hours of stress.

The security fix:

- `klauspost/compress` goes from v1.20.1 to v1.20.2, which fixes
  GHSA-fpmh-frq8-7rj8. A crafted zstd chunk made the decoder panic, so
  eictar stopped with a crash in place of exit 3. Two crafted chunks are
  enough, because the bad state stays in the library for the next chunk.
  A test decodes the input of the advisory, in eictar and in the second
  reader.

The other fixes:

- A create of an archive that did not exist could rename over one that a
  second create made in the meantime, and lose an append to it that had
  reported success. Now that create stops with exit 4 (design.md §9.6).
- The passphrase prompt read for ever, at the full speed of a CPU, when the
  terminal closed while it waited. The prompt used `term.ReadPassword`,
  which reads again after a read of 0 bytes. On Unix, the program now reads
  the line itself, and the end of the input stops it with exit 4
  (design.md §10.3). A CI run found it: `TestPromptReadFails` waited for 30
  minutes.
- The reader matched a CBOR map key to a field of another case: it read
  `salT` as `salt` in the crypto header, and `Path` as `path` in the index.
  Now a key is a field only when its bytes are equal, as
  `doc/format.md` §8.1 says. No writer of eictar made such a key, so each
  archive of eictar reads as before.

The format:

- After a compact of an archive whose members were all deleted, the index
  held `members` as null. `doc/format.md` §8.2 asks for an array, and the
  writer now writes an empty array. Each version reads both forms.
- `doc/format.md` §6 gives the bound on the window of a zstd frame that
  eictar applied without a statement: `max(1 MiB, chunk)`. The second
  reader applies it too. The bound does not change what eictar reads or
  writes.

The release:

- `make gate` runs every check of testing.md §5 on one commit, and
  `make vuln` scans for known vulnerabilities. The release workflow runs
  `make vuln` too.
- A release needs Go 1.27.2 or later, which fixes GO-2026-6604 in
  `os.Root` on Windows. The release workflow fetches the newest patch
  release of Go, and does not use an older one from the cache of the
  runner.

The format is still 1.0. v1.1.2 reads every earlier archive, and earlier
versions read what it writes.

**v1.1.3 makes zstd faster.** It passed the release gate (testing.md §5,
step 6) on c40b3ee: 1 hour of fuzzing for each target, and 8 hours of
stress. The commits after c40b3ee change only documents and
`build-fork.sh`, which is not part of the program.

The changes:

- `klauspost/compress` goes from v1.20.2 to v1.20.3. On one core, zstd
  decodes 40% faster on source code, and 17% faster on binary data. Level
  3 encodes 10% to 14% faster. The other levels, gzip and s2 have the same
  speed. zstd output is up to 0.4% smaller, and the gzip and s2 output
  does not change. The slow dictionary at level 10 and above stays
  (design.md §15.2).
- `BenchmarkCodecs` measures each codec without the file system
  (design.md §8.4). `bench/compare.sh` ran eictar with the configuration file of the
  user, so a setting there changed the codec of a row. It now runs eictar
  with `--no-config`, and its `zstd:level=3` rows give the level.
- design.md §15.2 has new measurements of the slow dictionary at level 12,
  and of a fix in a fork of the library. With the fork, `zstd:train` on
  20000 JSON files takes 3.3 s, against 23.8 s. `build-fork.sh` makes a
  local build with the fork. A release keeps the library in go.mod.

The tests:

- The mutation step of the gate on 36b4475 found a change in
  `Spool.spill` that no test detected. `TestPipelineFaults` made the write
  of the buffer fail only in some orders of its workers.
  `TestSpillWriteFails` now makes this write fail every time. It requires
  the error from the `Write` that spilled, and requires that the spill file
  is closed.

The format is still 1.0. v1.1.3 reads every earlier archive, and earlier
versions read what it writes.

**After v1.1.3, not yet in a release.**

- `completions/eictar.bash` gives tab completion in bash (design.md §10.8).
  It completes the options, the codecs and the other fixed values, and file
  names. Each release archive for a Unix system holds it, next to the man
  page. Two tests keep it in step with the parser.
- `--diff-extract` is for the time before you remove the source of an
  archive (design.md §9.10). It does all that `--diff` does. It also
  extracts each member, with the code of `-x`, into a scratch directory,
  compares the copy with the file byte by byte and by its metadata, and
  removes it. Thus it finds a fault of the digest code, or of extraction,
  that `--verify` and `--diff` cannot find. `--scratch-dir` chooses where
  the scratch directory goes. Times are compared to the precision of its
  file system. The stress tester runs it in half of its `--diff` steps.
- `tools/mutate`: the name of a mutant that removes a `!`, the first of its
  function, ended with a space. A line of `accepted.txt` cannot keep a
  space at its end, so no entry could accept such a mutant. The name now
  ends at the arrow. `TestKeys` covers it.
