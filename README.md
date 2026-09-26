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
drwxr-xr-x  phil/phil       0       -     -  -             2026-09-25 22:53:21  Documents
-rw-r--r--  phil/phil  288894   36269  87.4%  zstd:level=3  2026-09-25 22:53:21  Documents/numbers.txt
$ eictar -xf home.ect -d /tmp/restore Documents/numbers.txt
```

## Features

- **Compression for each file**: zstd (the default), xz, gzip, flate and s2,
  or none. Each append can use a different codec. `--list-codecs` shows
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

## Examples

The conventional extension is `.ect`. `-c` adds it to a name with no
extension, and the other operations find `home.ect` by the name `home`.

Create an archive with strong compression:

```
eictar -cf home.ect -C ~ --compress zstd:level=19 Documents
```

Archive a source tree with a dictionary:

```
eictar -cf src.ect -Z zstd:level=19,train project/
```

Create an encrypted archive, with a hidden index. The program asks for the
passphrase two times:

```
eictar -cef secret.ect --encrypt-index Documents
```

Add only the files that changed, then make sure that the archive is correct:

```
eictar -uf home.ect -C ~ --update-mode different Documents
eictar --verify -f home.ect
```

Extract only the PDF files below `Documents`, at any depth:

```
eictar -xf home.ect -R 'Documents/.*\.pdf'
```

Delete a directory, then remove the old generations and encode everything
again with xz:

```
eictar --delete -f home.ect Documents/old
eictar --compact -f home.ect --recompress xz:preset=9
```

Change the passphrase of an encrypted archive:

```
eictar --change-passphrase -f secret.ect
```

Show the archive's settings and generation:

```
eictar --info -f home.ect
```

A script can give the passphrase with `--passphrase-file FILE` or
`--passphrase-env VAR`. Default settings can come from `~/.eictarrc` and
`EICTAR_*` variables: see `eictar --show-config` and the manual page.

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

- Without `--encrypt-index`, a person with the archive can read the names,
  sizes, times and owners of the files, but not their content.
- An encrypted archive detects any change to its content or its index. A
  plain archive detects damage, but not a person who writes it again.
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
