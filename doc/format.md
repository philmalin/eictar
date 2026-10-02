# eictar archive format, version 1.0

This document specifies the bytes of an eictar archive. With it, you can
write a reader or a writer without the eictar source code.
`doc/design.md` gives the reasons for each choice. This document gives only
the rules.

The committed archives in `src/internal/archive/testdata/golden/` are
examples of this format:

- `plain.ect`: three generations, with a tombstone
- `encrypted.ect`: the same, encrypted, with a sealed index
- `dict.ect`: encrypted, with a sealed dictionary (§6.1)
- `shared.ect`: members that share the content of another (§8.5)

The passphrase of the encrypted examples is `golden`. The fixed test vectors
of the key schedule are in `src/internal/crypt/crypt_test.go`.

## 1. Conventions

- All integers are little-endian, except the chunk index in an AEAD nonce and
  in an AAD, which is big-endian (§7.3).
- `CRC-32C` is CRC-32 with the Castagnoli polynomial.
- `BLAKE3-256` is BLAKE3 with 32 bytes of output. "Keyed BLAKE3" is the keyed
  mode of BLAKE3 with a 32-byte key.
- `u64le(x)` is the 8-byte little-endian form of `x`, and `u64be(x)` is the
  big-endian form.
- `||` joins byte strings.
- "Refuse" means that a reader stops with an error and gives no content from
  the archive.

## 2. Layout

```
offset 0      file header         64 bytes
64            crypto header       crypto_header_len bytes (0 if not encrypted)
body start    member and dictionary blobs, old indexes and old trailers, in any order
index_offset  index               index_length bytes
file size-96  trailer             96 bytes
```

The conventional file name extension is `.ect`. A reader identifies an
archive by the magic of the file header (§3), not by its name.

The body starts at `64 + crypto_header_len`. The body has no framing: no
separator and no length is between two blobs. Only the index says where each
blob is. The body can also hold dead space: the blobs of deleted members, and
the indexes and trailers of earlier generations (§10).

## 3. File header

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | `45 49 43 54 41 52 1A 0A` ("EICTAR\x1a\n") |
| 8 | 2 | format_major | 1 |
| 10 | 2 | format_minor | 0 |
| 12 | 4 | header_flags | bit 0: the archive is encrypted. The other bits are 0. |
| 16 | 8 | created_unix_nanos | the time of creation, as a signed integer |
| 24 | 16 | archive_uuid | 16 random bytes |
| 40 | 4 | crypto_header_len | 0 when bit 0 of header_flags is 0. More than 0, and at most 65536, when it is 1. |
| 44 | 16 | reserved | zero |
| 60 | 4 | crc32c | CRC-32C of bytes 0 to 59 |

A reader refuses a header with a wrong magic or a wrong CRC. It also refuses
a format_major that it does not know, and a flag and a length that do not
agree.

A reader refuses a bit of header_flags that it does not know, and a reserved
byte that is not zero, as a version that it does not know. A later version
of the format uses them for a change that an older reader must not ignore. A
change that an older reader can ignore raises format_minor instead, and a
reader accepts a format_minor above its own. Readers before eictar v1.0.4 do
not make these checks.

## 4. Crypto header

The crypto header exists only when the archive is encrypted. It is
`crypto_header_len` bytes: a `u32le` length `n`, then `n` bytes of CBOR (§8.1)
that encode this map:

| Key | Type | Value |
|-----|------|-------|
| `v` | uint | 1 |
| `kdf` | text | `argon2id` |
| `salt` | bytes | 16 bytes, the Argon2id salt |
| `time` | uint | Argon2id passes, 1 to 64 |
| `memory` | uint | Argon2id memory in KiB, at least 8 × threads, at most 4194304 |
| `threads` | uint | Argon2id lanes, 1 to 255 |
| `aead` | text | `xchacha20poly1305` |
| `key` | bytes | 72 bytes, the wrapped data key (§7.1) |
| `recipients` | array | reserved. A reader refuses a crypto header that has it. |

A reader applies the limits on `time` and `memory` before it asks for a
passphrase. A crafted header can ask for a derivation that never ends.

## 5. Blobs and chunks

Each member with content has one blob: `len` bytes at offset `off` of the
file. The exception is a member that shares the content of another (§8.5). The blob is a sequence of chunks, back to back. The member's `chunks`
array gives the length on disk of each chunk, in order.

The **payload** of a member is the content that its blob stores. For a
member without `sparse`, it is the whole content, `size` bytes. For a member
with `sparse`, it is the bytes of the data segments, back to back (§9.3).

The payload is cut into plaintext chunks of `chunk` bytes. The last chunk
can be shorter, but it is never empty. An empty payload has no chunks, and
the member has no `chunk`.

Each plaintext chunk becomes a chunk on disk in two steps:

1. **Compress** it with the member's codec (§6). If the result is not
   shorter than the plaintext chunk, keep the plaintext chunk instead.
2. **Seal** it, if the archive is encrypted (§7.3).

A reader reverses the steps. After it unseals a chunk, it compares the length
with the expected plaintext length of that chunk. If they are equal, the
chunk is stored as it is, and the reader does not decompress it. If not, the
reader decompresses it, and the result must have exactly the expected length.
Compression never keeps a result that is as long as the plaintext, so this
test has only one meaning.

The expected plaintext length of chunk `i` is `chunk`, except for the last
chunk, which has the rest of the payload.

## 6. Codecs

The index has a catalog of codecs. Each member names an entry of the catalog
by its position, or `-1` for no codec. A catalog entry is a map with `name`
(text), `params` (a map from text to a number or a text), and `dict` (uint,
optional). The parameters record the settings of the writer. A reader does
not need them. `dict` is the id of the dictionary (§6.1) that the codec
used, and a reader needs it to decode.

| Name | One compressed chunk is |
|------|-------------------------|
| `zstd` | one Zstandard frame (RFC 8878). The writer puts a content checksum in the frame. |
| `flate` | one raw DEFLATE stream (RFC 1951) that ends with a final block |
| `gzip` | one gzip member (RFC 1952), with MTIME 0 and no name. A reader refuses a second member after the first. |
| `s2` | one S2 block: a uvarint of the decoded length, then S2 block elements (the block format of `github.com/klauspost/compress/s2`, a superset of the Snappy block format) |
| `xz` | one raw LZMA2 stream, with no `.xz` container, that ends with the end marker (a 0x00 control byte). The properties are lc=3, lp=0, pb=2. |

**For `xz`, a reader uses a dictionary of `max(4096, expected plaintext
length)` bytes.** The stream does not state its dictionary size, and a reader
must not take a larger number from anywhere else. The chunks are
independent, so no match reaches back further than the start of its chunk.

A decoder reads at most the expected plaintext length, and then one more
byte to prove that the stream ends there. A chunk that decodes to more or to
less is refused.

### 6.1 Dictionaries

A `zstd` catalog entry with `dict` compresses each chunk with a Zstandard
dictionary. The dictionary is in the Zstandard dictionary format (RFC 8878,
section 5): the magic `37 A4 30 EC`, then the dictionary id as a `u32le`.
The dictionary id is the `id` of its Dict map (§8.2). Each frame names the
id of its dictionary, and a reader refuses a frame whose id is different.

The dictionary blob is `len` bytes at offset `off`, one message. It is not
compressed. When `enc` is present, the blob is sealed (§7.6). Otherwise, it
is the dictionary as it is, and `len` equals `size`.

A reader checks a dictionary before it decodes a member with it:

- the tag, when it is sealed
- that its length is `size`
- its `digest`: BLAKE3-256 of the dictionary, keyed like the member digests
  (§8.3)
- that its magic and its id are correct

## 7. Cryptography

### 7.1 Keys

```
dataK    = 32 random bytes, made when the archive is created
KEK      = Argon2id(passphrase, salt, time, memory, threads, 32 bytes)
key      = nonce || XChaCha20-Poly1305(KEK, nonce, dataK, aad = "eictar/v1/wrap" || archive_uuid)
indexK   = HKDF-SHA-256(ikm = dataK, salt = empty, info = "eictar/v1/index"      || archive_uuid || u64le(generation))
authK    = HKDF-SHA-256(ikm = dataK, salt = empty, info = "eictar/v1/index-auth" || archive_uuid)
contentK = HKDF-SHA-256(ikm = dataK, salt = empty, info = "eictar/v1/content"    || archive_uuid)
memberK  = HKDF-SHA-256(ikm = dataK, salt = enc.salt, info = "eictar/v1/member"  || archive_uuid)
dictK    = HKDF-SHA-256(ikm = dataK, salt = enc.salt, info = "eictar/v1/dict"    || archive_uuid)
```

`key` is the field of the crypto header (§4): a 24-byte random nonce, then
the 32-byte sealed data key and its 16-byte tag. Each HKDF output is 32 bytes.
The info strings are ASCII, with no terminator. The passphrase is its bytes
as given, with no normalization.

A reader derives `KEK` and opens `key`. If the tag fails, the passphrase is
wrong. A change of passphrase writes a new `salt`, new Argon2id parameters
and a new `key`, but `dataK` and every subkey stay the same.

### 7.2 AEAD

The AEAD is XChaCha20-Poly1305: a 32-byte key, a 24-byte nonce and a 16-byte
tag after the ciphertext.

### 7.3 Chunks

Chunk `i` of a member (the first chunk has `i = 0`) is sealed with:

```
key   = memberK of the member
nonce = 16 zero bytes || u64be(i)
aad   = u64le(member.id) || u64be(i) || final
final = 0x01 for the last chunk of the member, 0x00 for the others
```

The chunk on disk is the ciphertext and the tag. It is 16 bytes longer than
the compressed or stored chunk.

A writer must give a member a new random `enc.salt`, and so a new `memberK`,
each time that it seals content for the member. The same key with the same
chunk index and different content uses one nonce two times.

### 7.4 Sealed index

When bit 0 of trailer_flags is 1, the index on disk is:

```
nonce || AEAD-seal(indexK, nonce, compressed index, aad = u64le(generation))
```

The nonce is 24 random bytes. A writer must not take the nonce from the
generation, because two different indexes can have the same generation.

### 7.5 Index digest

The trailer records a digest of the index bytes on disk:

```
digest = BLAKE3-256(archive_uuid || u64le(generation) || index bytes on disk)
```

In an encrypted archive, the BLAKE3 is keyed with `authK`, whether or not the
index is sealed. In a plain archive, it has no key. A reader checks the
digest before it unseals or decodes the index, and compares it in constant
time.

A reader must also refuse a plain archive when its user expected an
encrypted one. Someone who removes the encryption can write a plain index
with an unkeyed digest.

### 7.6 Sealed dictionary

A dictionary (§6.1) of an encrypted archive is sealed as one message:

```
key    = dictK of the dictionary, from its enc.salt
nonce  = 24 zero bytes
aad    = u32le(id)
blob   = AEAD-seal(key, nonce, dictionary, aad)
```

A writer must give each dictionary a new random salt. Each dictionary key
then seals one message only, so the fixed nonce is safe.

## 8. Index

### 8.1 Encoding

The index is encoded in these steps:

1. CBOR (RFC 8949) of the Index map (§8.2). Map keys are sorted bytewise.
   Arrays and maps have a definite length. There are no tags and no
   duplicate keys. Text strings can hold any bytes, because a path is not
   always UTF-8.
2. Zstandard, one frame, when bit 1 of trailer_flags is 1. A writer always
   sets it.
3. The seal of §7.4, when bit 0 of trailer_flags is 1.

A reader reverses the steps. It limits the decompressed index to 1 GiB, and
to 200 times the compressed index or 64 MiB, whichever is more. It limits
the number of members to 4194304.

### 8.2 Index map

| Key | Type | Value |
|-----|------|-------|
| `v` | uint | 1, the version of this schema |
| `gen` | uint | the generation, equal to the trailer |
| `codecs` | array | the catalog (§6). Absent when it is empty. |
| `dicts` | array | the Dict maps (§6.1). Absent when there are none. |
| `members` | array | the Member maps |

A Dict map:

| Key | Type | Value |
|-----|------|-------|
| `id` | uint | the dictionary id, 1 to 2^32 − 1, unique in the index. A writer takes it from 32768 to 2^31 − 1, the range that RFC 8878 leaves free. |
| `gen` | uint | the generation that added it |
| `size` | uint | the length of the dictionary, 1 to 1048576 |
| `digest` | bytes | 32 bytes (§6.1) |
| `enc` | map | `{ "salt": 16 bytes }`, when the archive is encrypted |
| `off` | uint | the blob offset |
| `len` | uint | the blob length: `size`, or `size + 16` when sealed |

### 8.3 Member map

| Key | Type | Presence | Value |
|-----|------|----------|-------|
| `id` | uint | always | unique in the index, never 0, never reused |
| `gen` | uint | always | the generation that added the member |
| `path` | text | always | the stored path (§9.1) |
| `type` | text | always | `reg`, `dir`, `symlink`, `hardlink`, `fifo`, `sock`, `chardev` or `blockdev` |
| `mode` | uint | always | permission bits with setuid, setgid and sticky: at most `07777` |
| `uid`, `gid` | uint | both or neither | the owner. Absent when the writer did not record it. |
| `uname`, `gname` | text | optional | the owner by name |
| `mtime` | int | always | nanoseconds since the Unix epoch |
| `atime`, `ctime` | int | optional | nanoseconds since the Unix epoch |
| `size` | uint | always | the logical length of the content. 0 for a type without content. |
| `link` | text | `symlink` only, and required there | the target of the link, as recorded |
| `hardlink` | uint | `hardlink` only, and required there | the `id` of a `reg` member |
| `data` | uint | `reg` only, optional | the `id` of the member whose blob holds this member's content (§8.5) |
| `rdev` | array of 2 uint | `chardev` and `blockdev` only, and required there | major, minor |
| `xattrs` | map, text to bytes | optional | extended attributes, POSIX ACLs included, with each name as the source platform gives it (`user.comment` on Linux and the BSDs, `com.apple.quarantine` on macOS). Names of 1 to 255 bytes, values of at most 65536 bytes, at most 1024 entries. |
| `sparse` | array of maps | `reg` only, optional | data segments, each `{ "off": uint, "len": uint }` |
| `digest` | bytes | required for `reg` | BLAKE3-256 of the payload (§5): keyed with `contentK` (§7.1) in an encrypted archive, with no key in a plain one |
| `codec` | int | always | a catalog position, or -1 |
| `chunk` | uint | when there are chunks | plaintext bytes in each chunk, at most 268435456 |
| `enc` | map | in an encrypted archive, on a member with a blob of its own | `{ "salt": 16 bytes }` |
| `off` | uint | when there is a blob | the offset of the blob in the file |
| `len` | uint | when there is a blob | the length of the blob |
| `chunks` | array of uint | when there are chunks | the length on disk of each chunk |
| `dead` | bool | tombstones only | true |

Only `reg` members have content. A member of another type has no `off`,
`len`, `chunks` or `chunk`, and its `size` is 0. A `reg` member with an empty
payload has no chunks.

A reader ignores a map key that it does not know. A writer that adds a key
that an older reader must not ignore changes `format_minor` or
`format_major`.

### 8.4 Checks

A reader refuses an index that breaks any of these rules:

- the rules of presence and type in §8.3, and the limits in them
- two members with the same `id`
- a `codec` that is not -1 and not a catalog position
- a catalog `dict` that names no Dict map, or that is on a codec other than
  `zstd`
- a Dict map that breaks the rules of §8.2, or two with the same `id`, or
  more than 1024 of them
- a `hardlink` whose `id` is not a `reg` member of the index. The target can
  be a tombstone.
- a `data` that breaks the rules of §8.5
- `sparse` segments that are empty, out of order, overlapping, or that end
  after `size`
- `chunks` whose total is not `len`
- a payload that does not need exactly the number of chunks in `chunks`: it
  must be more than `chunk × (n − 1)` and at most `chunk × n`
- a blob, of a member or of a dictionary, that does not lie inside
  `[body start, index_offset)`
- a count of members without `dead` that is not the trailer's
  live_member_count

### 8.5 Shared content

A `reg` member with `data` has the content of another member, its owner,
and no blob of its own. It has no `off`, `len`, `chunks`, `chunk` or `enc`,
and its `codec` is -1. A reader decodes the owner's blob, with the owner's
codec, chunk size, key and `id` (§7.3), and checks the owner's digest.

A reader refuses a member with `data` unless all of these are true:

- the owner is a `reg` member of the index, with a blob, and without `data`
- the owner has the same `size`, the same `sparse` and the same `digest`

The owner can be a tombstone.

### 8.6 Paths in the index

The index checks do not require stored paths. A reader can list an archive
with a bad path, so that a person can see what is in it. A reader that
extracts refuses the bad member (§9.1).

## 9. Members

### 9.1 Stored paths

A stored path is relative, with `/` between its components. No component is
empty, `.` or `..`, and the path does not start with `/`. The one exception is
the path `.`, for the root of the archived tree. A path is a sequence of
bytes, and it does not have to be UTF-8.

An extractor refuses a member whose path breaks this rule. It also refuses to
write through a symbolic link that an earlier member made. It does not apply
a member `.` to its destination. The archive does not own that directory,
and the member changes its mode, its owner and its times.

### 9.2 Hardlinks

A `hardlink` member has no content. It names a `reg` member, whose content
it shares. That member can be a tombstone: a newer generation can replace
one name of a hardlinked file, and the other names keep the old content.

### 9.3 Sparse files

A `reg` member with `sparse` is a file with holes. Its payload is the bytes
of the segments, in the order of the array. To rebuild the file, write each
segment at its `off`, and make the file `size` bytes long. The rest of the
file is zero.

## 10. Trailer and generations

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | "EICTRAIL" |
| 8 | 2 | format_major | equal to the header |
| 10 | 2 | format_minor | equal to the header |
| 12 | 4 | trailer_flags | bit 0: the index is sealed. Bit 1: the index is compressed. Bit 0 only in an encrypted archive. |
| 16 | 8 | generation | 1 for a new archive, 1 more for each later index |
| 24 | 8 | index_offset | inside the body, at or after the body start |
| 32 | 8 | index_length | the index ends at or before the trailer |
| 40 | 8 | prev_index_offset | the index of the generation before, or 0 |
| 48 | 8 | live_member_count | members without `dead` |
| 56 | 32 | index_digest | §7.5 |
| 88 | 4 | reserved | zero |
| 92 | 4 | crc32c | CRC-32C of bytes 0 to 91 |

A reader refuses a bit of trailer_flags that it does not know, and a
reserved byte that is not zero, as for the header (§3).

The last 96 bytes of the file are the trailer, and they are the commit
record. A reader uses only that trailer. It does not go back to an earlier
generation by itself.

A writer changes an archive in this order:

1. Write the new blobs after the **end of the file**. The old trailer stays
   where it is.
2. Write the new index, which lists every member, old and new, with `dead`
   on the members that this generation removes.
3. Make steps 1 and 2 durable, then write the new trailer with
   `generation + 1`, then make it durable.

If step 3 does not complete, the file does not end with a valid trailer, and
a reader refuses it. The repair is to find the last valid trailer before the
end, and to cut the file after it. A candidate is valid only when every check
of this document passes for a file that ends after it.

A compact writes a new file with the same header and crypto header, and
the same `archive_uuid`, because every `memberK` depends on it. It uses the
next generation, and a `prev_index_offset` of 0. A change of passphrase is a
compact with a new crypto header: a new `salt`, new Argon2id parameters and
a new `key` (§7.1). The blobs do not change.

## 11. Limits

| Item | Limit |
|------|-------|
| crypto_header_len | 65536 bytes |
| Argon2id `time` | 64 |
| Argon2id `memory` | 4194304 KiB |
| `chunk` | 268435456 bytes |
| decompressed index | 1 GiB, and at most 200 × its compressed size or 64 MiB, whichever is more |
| members in one index | 4194304 |
| dictionaries in one index, dictionary size | 1024, 1048576 bytes |
| xattr name, value, count | 255 bytes, 65536 bytes, 1024 |
