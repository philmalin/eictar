# eictar security audit

| | |
|---|---|
| Version reviewed | v1.0.1 |
| Fixes in | v1.0.2 |
| Date | 2026-09-26 |
| Follow-up review | the changes after v1.0.2, with fixes in v1.0.3, 2026-10-01 (§6) |
| Second follow-up | `--diff`, `-n`, and `--exclude` on a read, after v1.0.5, 2026-10-04 (§7) |
| Scope | the source code, the archive format, and encrypted archives |

## 1. Scope and method

The review read the code of each part where untrusted data enters, or where
the program acts with the rights of its user:

- the parser of an archive: the header, the crypto header, the trailer, the
  index, and every length, offset and count in them
- the decoder of each codec, against decompression bombs
- extraction: paths, links, special files, modes, owners and extended
  attributes
- the cryptography: the key schedule, the nonces, what each AAD binds, the
  sealed dictionary, and what an encrypted archive shows
- the writer: how it opens the files of a tree, its temporary files, and the
  archive path
- the passphrase and the configuration

"Tested" means that the review made the attack happen, before the fix. "Code"
means that the review found it in the code, and gives the place.

## 2. Summary

| # | Severity | Finding | Status in v1.0.2 |
|---|---|---|---|
| 1 | High | Extraction as root restored `security.*` extended attributes, file capabilities too | Fixed |
| 2 | High | A member `.` changed the destination directory itself | Fixed |
| 3 | Medium | Create followed a symbolic link that took the place of a file after the walk | Fixed |
| 4 | Medium | The archive path followed a link that another user planted in `/tmp` | Fixed |
| 5 | Medium to low | Extraction ignored the umask, and restored ACLs for any user | Fixed |
| 6 | Low | A small plain archive made a listing allocate 1 GiB | Fixed |
| 7 | Low | Dictionaries and shared content let an attacker test for a file, from the size of the archive | Documented |
| 8 | Low | A passphrase file that other users can read gave no warning | Fixed |
| 9 | Information | An unsealed index shows link targets and xattr values; other known limits | Documented |
| 10 | Low | The pool of decoders kept one decoder for each kind that the index named (after v1.0.2, not released) | Fixed in v1.0.3 |
| 11 | Medium | The walk followed a directory that became a link after its `lstat` (found after v1.0.5) | Fixed (§7) |
| 12 | Low | Control characters in member names went to the terminal as they are (found after v1.0.5) | Open (§7) |

Findings 1 to 4 matter most when root extracts an archive from someone else,
or archives a tree that other users can write. Each fix has a test in
`src/internal/archive/security_test.go`, `src/internal/meta/meta_unix_test.go`,
`src/internal/format/index_test.go` or `src/internal/cli/passphrase_test.go`.

## 3. Findings

### Finding 1. Privileged extended attributes (high)

**Where:** `applyXattrs` in `src/internal/archive/extract.go`, and
`ClassifyXattr` in `src/internal/meta/meta.go`. Found in the code.

**Problem.** Extraction put the names `security.*`, `trusted.*` and
`system.*` into one class, "privileged". It restored that class by default
when the process was root.

`security.capability` holds the Linux file capabilities of a program. An
archive can hold a program with `cap_setuid+ep`. Then an extraction by root
installs a program that any user can run to become root. `security.selinux`
also lets an archive choose the security label of a file.

The design required `-p` for the setuid bit, and said that extraction
restores "nothing that needs privilege or gives it". The capabilities went
around both.

**Fix.** Privileged attributes are restored only as root and with `-p`.
`-p` is now the one consent to restore everything exactly (design §7.7).
Without it, one notice counts what `-p` restores.

**Test.** `TestXattrPolicy` checks the decision for each class of attribute,
for root and for other users, with and without `-p` and `--no-xattrs`. The
decision is a function of its own, `xattrPolicy`, so that the test does not
need root.

### Finding 2. A member `.` changed the destination (high)

**Where:** `finishDirs` in `src/internal/archive/extract.go`. Tested.

**Problem.** The format allows the path `.`, the root of the archived tree.
The writer never stores it, but the reader accepted it. The last pass of
extraction then applied its mode and its times to the destination itself,
and its owner under `--preserve-owner`. A crafted archive made a destination
of 0755 into 0777. Extracted into `$HOME`, it makes the home directory open
to every user. As root with `--preserve-owner -d /`, it gives `/` to another
user.

**Fix.** Extraction removes a member `.` and says so in a notice. The
destination is never changed.

**Test.** `TestExtractDoesNotChangeTheDestination` extracts a crafted
archive, and checks that the destination keeps its mode, and the notice.

### Finding 3. A file that becomes a link after the walk (medium)

**Where:** `submitFile` and `sameContent` in
`src/internal/archive/capture.go`, and `sampleTree` in
`src/internal/archive/dict.go`. Found in the code.

**Problem.** The walk found each file with `lstat`. Then the writer opened
it with `os.Open`, which follows a symbolic link.

Between the two calls, a user who can write the directory can put a link to
`/etc/shadow` in place of a file. A backup by root then stores `/etc/shadow`
under that user's file name. A later restore of "my files" gives it to the
user. With `train`, parts of it also go into the dictionary.

**Fix.** `openWalked` opens with `O_NOFOLLOW`, except under `-h`, and then
makes sure that the open file has the device and the inode that the walk
saw. Otherwise the member fails, as for a read error. The capture, the
samples of a dictionary and `-u --update-mode=digest` all use it.

**Limit.** A file that someone deletes and creates again can get the same
inode number. Linux, NetBSD and OpenBSD give a freed number to the next file
at once. Such a file passes the check. That is safe: it holds only content
that the user can also write into the walked file. A link, or a hardlink
to another file, always has another inode, and the check refuses it.

**Tests.** `TestOpenWalkedRefusesASwap` puts a symbolic link, a hardlink to
another file, and another new file in place of a walked file. The first
version of the test deleted the walked file, and CI found that the new file
then often got its inode. `TestCreateSkipsAFileThatBecameALink` does the
same through the capture of a member.

### Finding 4. A planted link in the archive path (medium)

**Where:** `createTarget` in `src/internal/archive/writer.go`, and
`CompactArchive` in `src/internal/archive/mutate.go`. Found in the code.

**Problem.** The writer resolves `-f` with `filepath.EvalSymlinks`, and
renames the new archive over the target. Suppose that another user plants
`/tmp/backup.ect -> /etc/passwd`. Then `eictar -cf /tmp/backup.ect` by root
replaces `/etc/passwd`.

Linux refuses such a link to `open(2)` in a sticky directory that everyone can
write (`fs.protected_symlinks`). That rule protects `tar`. But the writer
resolved the link itself, so the rule never applied.

**Fix.** `checkLinks` applies the rule of the kernel to each link in the
path, for create, compact and change of passphrase. A link in such a
directory is followed only when it belongs to the caller or to the owner of
the directory. Otherwise the program stops with exit 3.

**Tests.** `TestMayFollow` checks the rule for links of other users, which a
test cannot make. `TestCheckLinksFollowsOwnLinks` checks that a link of
one's own in a sticky directory still works.

### Finding 5. The umask and ACLs on extraction (medium to low)

**Where:** `meta.FileMode` and `applyXattrs`. Tested.

**Problem.** Extraction gave each file the mode of the archive, exactly. An
archive's 0666 file and 0777 directory became files that every user can
write, whatever the umask of the user. POSIX ACLs were also restored by
default, and an ACL can give access to other users, as a mode can.
`tar` applies the umask for a user who is not root.

**Fix.** For a user who is not root, and without `-p`, each mode is less the
umask. ACLs are restored as root, or with `-p`.

**Test.** `TestExtractAppliesTheUmask` extracts a 0666 file and a 0777
directory with and without `-p`. `TestXattrPolicy` covers the ACLs.

### Finding 6. The expansion of the index (low)

**Where:** `DecodeIndex` in `src/internal/format/index.go`. Found in the
code.

**Problem.** A compressed index expanded up to `MaxIndexSize`, 1 GiB, and so
a plain archive of a few KiB made a listing allocate 1 GiB. An encrypted
archive was safe, because its keyed digest is checked before the index is
decompressed.

**Fix.** An index can also expand only to 200 times its compressed size, or
to 64 MiB, whichever is more. A real index compresses 5 to 20 times.

**Test.** `TestIndexExpansionIsBounded` decodes 100 MiB of zeros from a
small frame, and checks the refusal and the limits.

### Finding 7. Size side channels across files (low; documented)

**Problem.** Until M10 and M11, each file was compressed alone. Thus the
content of one file never changed the stored size of another. Now two
features work across files:

- **Shared content (§4.3 of the design).** A copy of a file that the
  archive holds adds almost nothing.
- **Dictionaries (§4.2).** A file that looks like the files of the
  dictionary compresses better.

Suppose that an attacker can put files into a tree that is archived again
and again, and can see the size of the archive. Then the attacker can test
if the archive holds a guessed file. With a dictionary, this is the attack
CRIME across files, which the design accepted only inside one member.
`--encrypt-index` hides the size of each member, but not the size of the
archive.

**Response.** Documented in the design (§14.1), the man page and the
README. For such a tree, use `--no-dedup` and no `train`. No code change:
the features are useful, and the risk needs an unusual setting.

### Finding 8. A passphrase file that others can read (low)

**Where:** `warnIfInsecureSource` in `src/internal/cli/passphrase.go`.

**Problem.** `--passphrase-file` read a file that every user can read, with
no message.

**Fix.** A warning, as ssh gives for a key: the file can be read by other
users, and `chmod 600` it. The program still reads it.

**Test.** `TestPassphraseFileThatOthersCanRead` checks the modes 0600, 0400,
0640 and 0644.

### Finding 9. Information

- **An unsealed index shows more than names.** It also shows link targets,
  and the value of each extended attribute. A value can say much: macOS
  records the address that a file came from, in
  `com.apple.metadata:kMDItemWhereFroms`. Documented in the design (§14.1).
  `--encrypt-index` hides the index.
- **XChaCha20-Poly1305 does not commit to its key.** One ciphertext can open
  under two keys, with work. This matters for a service that tests
  passphrases for someone else. It does not matter for an archive that its
  owner opens.
- **Known and documented limits:**
  - The program sets the passphrase and the data key to zero, but not the
    subkeys (design §14.2).
  - An archive can ask for up to 64 passes of Argon2id before its
    passphrase is checked (§6.2).
  - A rollback to an older genuine archive, and a downgrade to plaintext
    without a passphrase source, are not detected (§14.4).

## 4. What the review found sound

- **Paths on extraction.** Every file operation goes through `os.Root`.
  Special files and link times use `*at` calls with one name, on a directory
  descriptor. The review found no way out of the destination. It tried
  `..`, an absolute path, a planted link, and a hardlink to a file that the
  run did not write. A file is written to a temporary name with `O_EXCL`, and
  renamed into place, so the program never writes through an existing
  hardlink.
- **Decompression bombs.** Each codec has a bound.
  - zstd: a frame that declares a window of 512 MiB or 2 GiB is refused
    before any allocation (tested).
  - s2: the declared length must be the length that the index gives.
  - gzip and flate: at most the expected length is read, and one more byte.
    gzip refuses a second member.
  - xz: the dictionary is at most the chunk.
- **Allocation.** Each number that sizes an allocation has a limit, which
  the program applies first. These numbers are:
  - the size of the index, the chunk size and the crypto header
  - the number of members and of dictionaries
  - the size of a dictionary
- **Keys and nonces.**
  - Each archive, member and dictionary has its own key from HKDF.
  - Each member and dictionary gets a new random salt when it is sealed:
    recompress, compact and change of passphrase never use a nonce two
    times.
  - The nonce of the index is random.
  - The AAD binds a chunk to its member, its place and the last chunk.
  - Digests are keyed in an encrypted archive, and every comparison takes
    constant time.
  - The data key is wrapped with its tag, so a wrong passphrase is found
    before any other read.
- **Shared content** checks an old owner before it first uses it, and reads
  a shared blob with the key and the id of its owner.
- **Temporary and spill files** have random names, are created with
  `O_EXCL` and mode 0600, and a spill file is removed from its directory at
  once.
- **Regular expressions** use RE2, in linear time. Each expression must
  compile alone before the anchors go around it, so it cannot break out of
  them.

## 5. Recommendations for later

- Run the fuzz targets for longer, and add one for the parser of a zstd
  dictionary from an archive. A plain archive can give any bytes as a
  dictionary, with a correct unkeyed digest.
- Consider a separate option for privileged attributes, if users want
  capabilities without exact modes.
- Review the code again when a feature adds a new place where the archive's
  data decides what the program does.

## 6. Follow-up review for v1.0.3

This review applies recommendation 3 of §5 to the changes after v1.0.2:

- the name of the archive: a name that is an existing directory gets `.ect`,
  even when it has a dot
- parallel `--verify`, with members in batches
- the pool of decoders, and a set of decoders for each worker of `--verify`
- the default of `-j`: three quarters of the CPUs

It also does recommendation 1.

### Finding 10. One decoder for each kind in the index (low)

**Where:** `takeDecoder`, `giveDecoder` and `decoderSet` in
`src/internal/archive/reader.go`. Commit 3f84d7f added them after v1.0.2.
No release had them.

**Problem.** The pool, and the set of each worker, keep an idle decoder for
each kind: each codec, chunk size and dictionary. These values come from the
index, and so from the attacker. A chunk size is valid for a member of one
chunk when it is at least the size of the content. Thus each member of a
hostile archive can have a kind of its own. Each idle zstd decoder keeps
about 17 KB of tables, and its dictionary. An index can hold 4194304
members. Thus `--verify` or extraction of a small archive could keep many GB
of decoders. Before the pool, the reader closed each decoder after its
member.

**Fix.** The pool and each set keep at most 16 kinds (`maxDecoderKinds`). A
decoder of a further kind is closed after its member. A real archive has one
kind for each catalog entry and chunk size that it uses.

**Test.** `TestDecoderKindsAreBounded` decodes one member with 40 chunk
sizes, through the pool and through a set. Each keeps 16 kinds, and each
decode is correct. With no bound, the test fails: each keeps 40.

### The other changes

- **No state goes from one member to the next.** A decoder is used again
  only for the same codec, chunk size and dictionary id. Thus a decoder made
  with one dictionary never decodes a member whose catalog names another.
  zstd resets its frame state at the start of each `DecodeAll`. The other
  codecs make a new reader for each chunk. A decoder that returns an error
  is closed, not used again (`TestDecoderPoolDropsFailedDecoder`).
- **Parallel `--verify`** bounds its workers by the chunk sizes in the
  index, as extraction does (design §8.3). A batch that waits holds only one
  error for each member, not content. The report keeps the order of the
  index, so the output does not depend on the workers
  (`TestVerifyInParallel`).
- **The name of the archive** changes only which file name the program uses.
  The archive is then opened as before, with the protection of finding 4.
- **The default of `-j`** has no effect on security.

### Recommendation 1: fuzzing

`FuzzZstdDictionary` (package `codec`) is new. It follows the reader with an
arbitrary dictionary: the check of the id, the decoder made from the
dictionary, and a decode with it. `make fuzz` runs it with the other
targets.

Each of the six targets ran for 5 minutes, on 32 CPUs (`make fuzz
FUZZTIME=5m`). None found a failure.

| Target | Inputs | Corpus |
|---|---:|---:|
| `FuzzHeaderUnmarshal` | 215,835,789 | 12 |
| `FuzzTrailerUnmarshal` | 220,831,787 | 11 |
| `FuzzDecodeIndex` | 178,932,605 | 872 |
| `FuzzUnmarshalCryptoHeader` | 200,141,852 | 621 |
| `FuzzDecoders` | 106,053,599 | 1026 |
| `FuzzZstdDictionary` | 121,155,063 | 600 |

### Status of the recommendations

1. Done: the new target, and the longer run above.
2. Open. It is a decision about a feature, not a fault.
3. Done for v1.0.3, in this section. It stays a rule for later changes.

## 7. Follow-up review of `--diff` and `-n`

This review applies recommendation 3 of §5 to the changes after v1.0.5:

- `--diff` (design §9.8): member paths from the archive decide where the
  program reads the disk
- `-n`, the dry run (design §9.9): with `-x`, member paths decide where the
  program looks under the destination
- `--exclude` on a read: a matched directory takes its contents
- `-h` on the command line: refused where it means nothing

The review read `diff.go`, `plan.go` and the walk that both use, and made
the attacks below happen.

### Finding 11. A directory that becomes a link during the walk (medium)

**Where:** `walk` and `walkChildren` in `src/internal/archive/walk.go`.
Found in the code, and tested. The walk is older than `--diff`. It is the
walk of create, append, update, `--diff`, `-n` and the samples of a
dictionary.

**Problem.** The walk finds a directory with `lstat`, and then reads it with
`os.ReadDir`, by its path. The path of each entry below it is the path of
the directory and the name. Each later call resolves the whole path again,
and follows a link in it.

Between the `lstat` and the `ReadDir`, a user who can write the parent can
put a link in place of the directory. The walk then reads the directory that
the link points to. The `lstat` of each entry goes through the link, so
`openWalked` (finding 3) finds the device and the inode that it expects:
`O_NOFOLLOW` applies to the last name of a path only. Thus:

- A backup by root of a tree that other users can write stores files from
  outside the tree, under that user's names, as finding 3 did for one file.
- `--diff` by another user, with an archive from the attacker, tells the
  attacker if a file outside the tree has the content that a member names.
  The attacker must also see the output.

The check of `--diff` on the start of each walk (`rootThere`, through
`os.Root`) does not help. The walk itself starts again from the path.

**Test.** A test walked a directory while another goroutine put a link to
another directory in its place, and back, in a loop. The walk reported a
file of the other directory after 3749 walks, in 0.2 s.

**Fix.** The walk holds each directory that it enters open, as an `os.Root`,
and does each operation below it through that root, by one name: the
`lstat`, the `readlink`, the open of a file, and the open of a
subdirectory. It opens a subdirectory, and checks that it has the device and
the inode of the `lstat`, before it reads it. Otherwise the directory fails
as a member that changed, and the walk does not enter it. `os.Root` follows
a link that stays inside the directory, and does not take `O_NOFOLLOW`. The
check of the device and the inode refuses what such a link opens, for a
directory and for a file (`openWalked`).

The extended attributes come from the open file or directory
(`ReadXattrsFile`: `flistxattr` and `fgetxattr` on Linux and macOS,
`extattr_list_fd` and `extattr_get_fd` on FreeBSD and NetBSD). `--diff`
opens each file during the walk, and its workers read the open file. The
samples of a dictionary come from a second walk, which reads each file that
the first walk chose while it holds the file's directory. `--diff` starts
each walk inside its `os.Root`. The open of a file has `O_NONBLOCK` too, so
that a pipe in the place of a file does not stop the open.

**Limits.**

- A path that the user names is opened from its parent, by the path. The
  user chose that path.
- A directory that the process cannot open, for want of permission, is
  archived empty, as before. Its attributes then come from the path. Root
  can open every directory, so this does not apply to a backup by root.
- `-h` follows links on purpose. A link that it follows is followed by its
  path, and the walk holds the directory from there.

**Tests.** `TestWalkRefusesADirectoryThatBecameALink` puts a link in the
place of a directory between its `lstat` and its open: the walk does not
enter it, and reports it as changed. `TestWalkHoldsTheDirectoryItOpened`
puts the link there after the walk opened the directory, between two of its
entries: the next entry is still the file of the tree. Each test fails when
its part of the fix is taken out. The race of the first test, in a loop,
made 206,703 walks in 10 s with no walk out of the tree.

**Cost.** On 20,000 small files in 2,000 directories, create took the same
time. `--diff` took 0.175 s, against 0.14 s before: it opens each file in
the walk, not in a worker.

**Status:** fixed.

### Finding 12. Control characters in names go to the terminal (low)

**Where:** each output of a member path: `-t`, `-v`, `-n`, the lines of
`--diff`, and the messages that name a member. Found in the code, and
tested.

**Problem.** A name on Linux can hold any byte except `/` and NUL, and the
index of a crafted archive can hold any name. The program writes a name to
the terminal as it is. An escape sequence in a name can change the colours,
move the cursor, write over the lines before it, or hide other names. Some
terminals do more with some sequences. Thus `-t` or `-n` of an archive from
someone else can show a listing that is not the content. A test archived the
name `a<ESC>[31mRED`, and `-t` and `-cn` wrote the ESC byte.

**Proposed fix.** When it writes to a terminal, the program shows a control
character in a name as an escape, as `ls` does. `--json` already escapes
it. Output to a pipe or a file can stay exact, for a script that reads the
names.

**Status:** open.

### The other changes

- **`--diff` checks every member path** as extraction does (design §7.5),
  before it reads the disk. A path with `..`, an absolute path, or a path
  that is not canonical stops the run with exit 3.
- **The start of each walk** is checked through `os.Root`. A link on disk
  that leads out of the directory stops the run with exit 3
  (`TestDiffDoesNotLeaveTheBaseThroughALink`). The fix of finding 11 starts
  the walk inside that root too.
- **The target of a hardlink** is found through `os.Root` too. A target path
  that `--exclude` left out, and that the path check did not see, cannot
  leave the directory.
- **What `--diff` shows** of the disk: the kind of each difference, modes,
  owners by number, times, and the target of a link, in quotes. It shows the
  names of the extended attributes that differ, not their values. It reads
  no member data, and the digests that it compares are keyed in an
  encrypted archive.
- **A dry run of `-x`** looks only under the destination, through
  `os.Root`, and refuses an unsafe path with exit 3, as extraction does. When
  the destination does not exist, it reads nothing on disk. It shows which
  paths exist under the destination, which the user can see anyway.
- **A dry run of `-c`, `-r` and `-u`** walks only the paths that the user
  gave. The archive decides only what happens to each path, by the rules of
  the real run. `-u --update-mode=digest` reads each file with `openWalked`.
  A dry run of `--delete` reads nothing on disk.
- **No dry run takes a lock** or opens the archive for writing. A writer at
  the same time is safe: a reader sees one complete generation.
- **`--exclude` on a read** only removes members from a selection. It cannot
  add one.
- **`-h`** on an operation that does not walk was ignored. It is now a usage
  error, as each other option of the walk is. This has no effect on
  security.

### Status of the recommendations

3. Done for these changes, in this section. Finding 11 is fixed, and
   finding 12 is open. It stays a rule for later changes.
