# eictar - Encrypted Individually-Compressed TAR

> This statement and `doc/design.md` are kept in sync. This file says *what*
> the program must do and *why*; the design document says *how*. When a
> requirement changes, change it here first, then carry it into the design.

## Goal

I want to write a program similar to `tar`, however the packaged contents of
the archive are individually compressed and, if elected to encrypt,
individually encrypted.


## Constraints

1. The program is to be written in Go and use of multithreading is to be
   expected.
1. The user will be able to choose the compression algorithm (e.g. zstd, xz,
   etc.).  Files may have different compression algorithms if added to the
   archive separately.  However, if files are added at the same time then they
   will have the same compression algorithm.
1. Encryption uses Go's state-of-the-art libraries: XChaCha20-Poly1305 for
   the content and Argon2id to turn the passphrase into a key.  `ccrypt` is
   therefore not required and is not used.  All files share the same
   encryption secret key (unless the files themselves have been separately
   encrypted, but that is outside the scope of eictar's purview).
1. Both encryption and compression are optional, in which case it will act
   similar to TAR.
1. An index will be maintained so listing is fast.  The index will contain all
   relevant information about the compression algorithm, encryption details,
   unix permissions, extended attributes.
1. Each compression algorithm supported will have their separate set of
   attributes that the user can select (compression level, number of threads,
   etc.).
1. Dependencies must be pure Go.  Third-party modules are welcome, but no CGO
   and no shelling out to external binaries, so that the result is a single
   static cross-compilable binary.
1. The archive is one self-contained file.  The index sits at the end of it,
   so that adding files later is an append, not a rewrite.
1. Members may be deleted and replaced.  Space from deleted members is
   reclaimed by an explicit compaction step, not automatically.
1. The archive must record metadata faithfully: symlinks, hardlinks, device
   nodes, sparse files, extended attributes, ACLs, ownership and
   nanosecond-resolution timestamps.
1. Integrity must be verifiable.  Every member carries a digest of its
   content, and the archive can be checked without being extracted.
1. A crash part way through writing must never damage what was already in the
   archive.
1. Two runs that change the same archive at the same time must never damage
   it, for example two backup jobs that overlap.  The second run does not
   wait: it stops with a clear error, and the first one finishes normally.
   Reading an archive while another run changes it is always safe.
1. Paths are stored relative to the archive, never absolute.  A leading `/`
   or `..` is removed when the file is added, and the program says once that
   it did so.  This follows `tar` and `zip`: an archive holds a portable tree,
   not a set of filesystem locations, so an archived `/etc/passwd` unpacks
   under the chosen directory and not over the system file.  There is no
   option to keep absolute paths.  On extraction the check is made again,
   because an archive may have been written by another program.
1. Extraction can be directed at a chosen directory with `-d`, as `unzip`
   does.  The directory is created if it is not there.  Nothing is ever
   written outside that directory, and in particular an archive must not be
   able to write through a symbolic link that points out of it.
1. Paths can be selected by regular expression, as well as by name and
   glob: on the paths to add, and on the members to list, extract, verify
   or delete.  The expression matches the whole stored path.
1. Frequently used parameters, compression above all, must be settable
   without typing them every time: by environment variable and by a
   configuration file (`.eictarrc`).  The command line wins over the
   environment, which wins over the configuration file.  The configuration
   file is the user's own, in the home directory, or one named explicitly with
   `--config`.  There is no configuration file read from the current
   directory: the program must not change behaviour because of where it was
   run from.  What the operation is (create, extract, and so on), which
   archive to use, and the passphrase are never taken from the environment or
   a configuration file.
1. The program must be tested extensively, at two levels, and the tests are
   part of the deliverable rather than an afterthought:
   - **Unit tests** in the code, next to each package.  Every format
     structure, codec, key-schedule step and path rule has its own test.  No
     milestone is finished until its tests are written and passing.
   - **Operational tests** that drive the built binary end to end, the way a
     user drives it, against real files on a real filesystem.  These cover
     the full lifecycle: create, list, extract, append, delete, replace,
     compact, verify.
   The test suite must also prove the hard parts: that a tampered archive is
   detected, that a crash at any write step leaves the archive intact, that
   a second run that changes the archive at the same time is refused, that
   extraction cannot write outside its destination, and that metadata
   survives a round trip untouched.


## Decisions

These resolve the open questions in the constraints above.  `doc/design.md`
gives the full reasoning and the exact formats.

| Topic | Decision |
|-------|----------|
| Container layout | Append-only body, index in a footer, fixed-size trailer at the end of the file as the commit record |
| Encryption | XChaCha20-Poly1305 AEAD over 4 MiB chunks, a separate derived subkey per member.  A random data key per archive, sealed under a key that Argon2id derives from the passphrase, so the passphrase can change (`--change-passphrase`) without encrypting the content again |
| Index encryption | Optional, `--encrypt-index`, off by default.  An unencrypted index reveals file names, sizes and permissions.  In an encrypted archive the member digests are keyed, so they reveal nothing about the content |
| `ccrypt` | Dropped.  `golang.org/x/crypto` covers the requirement |
| Dependencies | Pure-Go third-party modules allowed.  No CGO, no external binaries |
| Default codec | zstd, alongside xz, gzip, flate, s2 and stored |
| Dictionaries | `-Z zstd:train` trains a zstd dictionary from the files and stores it in the archive, encrypted when the archive is.  Each member stays independent |
| Concurrency | Member order inside the archive is not significant, so a single writer appends whichever worker finishes first |
| CLI style | Classical UNIX options, not subcommands.  The operation is chosen by an option letter (`-c`, `-r`, `-t`, `-x`), short options bundle (`-cvf`), and every short option has a long form |
| Archive name | The conventional extension is `.ect`.  Create adds it to a name that has no extension, and the other operations find that name |
| License | GPL-3.0.  The name "eictar" is reserved: a modified version that is distributed must use another name (`TRADEMARKS.md`) |


## Out of scope for v1

- **Delta storage between versions.**  When a stored file changes, we replace
  it: the new content goes in whole and the old member is tombstoned.  We do
  not keep a base version plus a chain of patches.  A file appended N times
  therefore holds N full copies until it is compacted.
- **Incremental archiving of a tree** in the sense of `tar
  --listed-incremental`, where a snapshot file records what was archived last
  time so the next run takes only the changes.  This sits above the format and
  can be added later without changing the archive layout.
- **Content deduplication**, meaning: storing identical content once, where
  identical is decided by the content itself rather than by the inode.
  Hardlinks are detected and stored once; two unrelated copies of the same
  file are not.  Neither whole-file dedup nor chunk-level dedup (the
  content-defined chunking that borg and restic use) is in v1.  Whole-file
  dedup is cheap to add later and `doc/design.md` §15 records what it needs.
- Public-key recipients.  The format leaves room for them.
- Reading an archive from a pipe.  The footer index needs a seekable file.
- Archive-wide signatures.
- Metadata on platforms other than Linux, macOS, FreeBSD, NetBSD and
  OpenBSD.  On other platforms the program archives content, directories and
  links only.  The four platforms besides Linux have the limits in
  `doc/design.md` §15.1: macOS records no ACLs and does not create pipes,
  and OpenBSD has no extended attributes.  The tests run on all five
  platforms in CI.
