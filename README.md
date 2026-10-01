# eictar

eictar is an archiver like `tar`. It compresses each file separately, and it
can encrypt each one. The index is at the end of the archive. Thus eictar can:

- list an archive without a read of its content
- extract one file without a decompression of the files before it
- append, update and delete files without a new copy of the archive
- limit damage to the files whose bytes are damaged

```
$ eictar -cf home Documents
eictar: creating home.ect
$ eictar -tvf home.ect
drwxr-xr-x  phil/phil       0       -     -  -              2026-09-25 22:53:21  Documents
-rw-r--r--  phil/phil  288894   32498  88.8%  zstd:level=12  2026-09-25 22:53:21  Documents/numbers.txt
$ eictar -xf home.ect -d /tmp/restore Documents/numbers.txt
```

## Features

- **Compression for each file**: zstd (the default, at level 12), xz, gzip,
  flate and s2, or none. Each append can use a different codec. `--list-codecs` shows
  the codecs and their parameters.
- **Dictionaries**: `-Z zstd:train` learns the text that the files share,
  such as license headers and imports, and stores it once in the archive.
  Many small, similar files then compress better, and each file can still be
  extracted alone.
- **Encryption** (`-e`): XChaCha20-Poly1305 over chunks, with a key that
  Argon2id derives from a passphrase. Each file has its own subkey.
  `--encrypt-index` also hides the names, sizes and times.
- **Selection** by path, glob or regular expression. `-R RE` keeps only
  the paths that the expression matches in full, when you add files and
  when you list, extract, check or delete them.
- **Identical files stored once**: a file whose content the archive already
  holds shares that data, in the same run or in a later append.
  `--no-dedup` stores each copy in full.
- **Changes in place**: `-r` appends, `-u` adds only what is out of date,
  and `--delete` removes. Each change writes a new generation after the old
  one, so a crash cannot damage what the archive held before. `--compact`
  removes the old generations.
- **Checks**: each file has a BLAKE3 digest. `--verify` checks every digest
  and every authentication tag without an extraction. `--repair` recovers
  an archive after a crash in the middle of a change.
- **Metadata**: permissions, owners, times, hardlinks, symbolic links, sparse
  files, extended attributes and POSIX ACLs (on Linux), pipes and device nodes.
- **Parallel work**: `-j` workers compress and encrypt, inside a memory
  limit.

## Install

With Go 1.27 or later:

```
go install github.com/philmalin/eictar/src/cmd/eictar@latest
```

Or download a binary for your platform from the
[releases](https://github.com/philmalin/eictar/releases) page. Each release
has a `SHA256SUMS` file.

Or build from a clone:

```
make build            # the binary is .build/eictar
make check            # the unit and operational tests
man ./doc/eictar.1    # the manual page
```

## Common tasks

### Create, list and extract

```
eictar -cf photos Pictures             # makes photos.ect
eictar -tf photos                      # the paths
eictar -tvf photos                     # a long listing, as tar -tv
eictar -xf photos                      # extract here
eictar -xf photos -d /tmp/restore      # extract into /tmp/restore
```

The conventional extension is `.ect`. `-c` adds it to a name with no
extension, and the other operations find `photos.ect` by the name `photos`.
A name that is a directory gets `.ect` even when it has a dot, so
`eictar -cf v1.5 v1.5` makes `v1.5.ect`.
Paths are stored relative: `-C DIR` changes to DIR first, so that
`eictar -cf home -C ~ Documents` stores `Documents/...`.

With no options, eictar uses these defaults:

| Setting | Default |
|---|---|
| compression | zstd at level 12 |
| chunk size | 4 MiB |
| workers (`-j`) | the number of CPUs |
| memory for data in flight | a quarter of the RAM |
| identical files | stored one time (`--no-dedup` turns this off) |
| encryption | off |
| extraction | replaces existing files, and restores permissions (less the umask) and times, not owners |

`eictar --show-config` shows each setting, and where its value came from.

### Encryption

```
eictar -cef secret Documents                    # asks for a passphrase two times
eictar -cef secret --encrypt-index Documents    # also hides the names and sizes
eictar -tf secret                               # asks for the passphrase
eictar -xf secret --passphrase-file ~/.secret   # for a script: the first line of the file
eictar --change-passphrase -f secret            # asks for the old one, then the new one
```

You choose encryption when you create the archive. Every later operation
uses the same passphrase, and eictar asks for it for every operation, a
listing too. Without `--encrypt-index`, the names, sizes and times are still
readable with other tools, but the content is not. Use `--encrypt-index` to
keep them secret too.

### Compression

```
eictar -cf a Documents                     # zstd, level 12 (the default)
eictar -cf a -Z zstd:level=3 Documents     # faster, a little larger
eictar -cf a -J Documents                  # xz: smaller, slower
eictar -cf a -z Documents                  # gzip
eictar -cf a -Z s2 Documents               # very fast, larger
eictar -cf a -Z none Documents             # no compression
eictar --list-codecs                       # every codec and its parameters
```

The zstd library of eictar has four speeds, not 22 levels. Levels 1 and 2
are the fastest, 3 to 5 the default speed, 6 to 9 better, and 10 to 22 the
best. Thus `level=12` and `level=19` make the same archive. On source code,
level 12 is about 5% smaller than level 3 and about 3 times slower to
create. Extraction is as fast at every level.

### Many small, similar files: a dictionary

```
eictar -cf src -Z zstd:train project           # a dictionary of 112 KiB
eictar -cf src -Z zstd:train=1M project        # a larger one, for a large tree
```

`train` learns the text that the files share, such as license headers and
imports, and stores it one time in the archive. Each file can still be
extracted alone. The gain is largest for many small text files, and near
zero for large or compressed files. A later `-r` or `-u` with `train` uses
the same dictionary.

For large files, `long` gives zstd a larger window. The window works only
inside one chunk, so give a chunk size to match:

```
eictar -cf images -Z zstd:long --chunk-size 128MiB disk-images
```

### Backups: add, update, delete and compact

```
eictar -uf home -C ~ --update-mode different Documents   # add only what changed
eictar -rf home -C ~ Documents/new.txt                   # add, replacing an older copy
eictar --delete -f home Documents/old                    # mark as deleted
eictar --compact -f home                                 # remove deleted data and old copies
eictar --compact -f home --recompress xz                 # the same, and encode everything again
```

Each change adds a new generation after the old one. A crash does not damage
what the archive held before, and `eictar --repair -f home` removes an
incomplete generation. Deleted and replaced files keep their space until
`--compact`. Use `--update-mode different` for backups: the default,
`newer`, misses a file that a restore from backup made older.

### Select files

```
eictar -xf home Documents/letters              # a directory and its contents
eictar -tf home '*.pdf'                         # a name at any depth
eictar -cf src --exclude '*.o' project          # leave files out
eictar -xf home -R 'Documents/.*\.pdf'          # a regular expression, on the whole path
eictar -cf src --exclude-regex '.*/build' project
```

A regular expression must match the whole stored path, such as
`Documents/2026/tax.pdf`. In an expression, `.` is any character, so write
`\.` for a dot, and put the expression in single quotes.

### Check an archive

```
eictar --verify -f home       # decode everything, and check every digest
eictar --info -f home         # size, codecs, dictionaries, shared content, dead space
eictar -tvvf home             # the long listing, with digests and totals
```

In `-tv`, a file that shares the data of an identical file ends with
`same as PATH`.

### Settings in a file

Put the settings that you always use in `~/.eictarrc`:

```ini
workers = 8
exclude = *.o

[codec.zstd]
level = 12
train = on
```

An option on the command line wins over the file: `-Z zstd:train=off`
turns `train` off for one run. `--no-config` ignores the file and the
`EICTAR_*` variables.

## Exit status

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Some files failed, under `--keep-going` |
| 2 | A usage error. Nothing was changed. |
| 3 | The archive failed a check: damage, a wrong passphrase, or a failed tag |
| 4 | Any other error, for example I/O |

## Platforms

Linux, macOS, FreeBSD, NetBSD and OpenBSD, on amd64 and arm64. The CI
workflow runs every test on each of these platforms. Some metadata is not
available on each platform: the manual page gives the details.

## Security notes

- eictar asks for the passphrase for every operation on an encrypted
  archive, a listing too. Without `--encrypt-index`, other tools can still
  read the names, sizes, times and owners of the files, but not their
  content.
- An encrypted archive detects any change to its content or its index. A
  plain archive detects damage, but not a person who writes it again.
- Extraction restores nothing that gives privilege: no setuid bits, no file
  capabilities or other privileged attributes, and no owner. `-p` restores
  exact modes and those attributes. Use it only for an archive that you
  trust.
- Suppose that other users can add files to a tree that you archive again
  and again, and can see the size of the archive. Then use `--no-dedup` and
  no `train`: shared content and dictionaries let them test for a guessed
  file.
- [`doc/Security_Audit.md`](doc/Security_Audit.md) records the security
  review of v1.0.1 and the fixes of v1.0.2.
- A change of passphrase does not remove old copies of the archive. Such a
  copy still opens with the old passphrase.

## Documentation

- [`doc/eictar.1`](doc/eictar.1): the manual page.
- [`doc/format.md`](doc/format.md): the archive format, for a person who
  writes another reader.
- [`doc/design.md`](doc/design.md): the design and the reasons for it.

## License

eictar is free software under the GNU General Public License, version 3
([`LICENSE`](LICENSE)). The license does not grant the right to use the
name "eictar" for a modified version: see [`TRADEMARKS.md`](TRADEMARKS.md).
