package crypt

import (
	"bytes"
	stdhkdf "crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"lukechampine.com/blake3"
)

// specGenerations has a value in each byte of the generation. Below 256 only
// the low byte is not zero, and a mistake in the order of the other seven
// bytes gives the same key.
var specGenerations = []uint64{0, 1, 255, 256, 65536, 0x0102030405060708, 1<<63 | 0xfe, ^uint64(0)}

// specKey is a key of doc/format.md 7.1, computed from the text of the
// specification with the standard library: HKDF-SHA-256, an info string, the
// archive id, and u64le where the specification gives it. It shares no code
// with keys.go.
func specKey(t *testing.T, dataKey, salt []byte, info string, uuid [16]byte, extra []byte) []byte {
	t.Helper()
	full := append(append([]byte(info), uuid[:]...), extra...)
	k, err := stdhkdf.Key(sha256.New, dataKey, salt, string(full), 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func u64le(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

// TestKeyScheduleMatchesSpec: each subkey and the keyed index digest agree
// with doc/format.md 7.1 and 4, for generations that use all eight bytes.
// TestKeyScheduleVectors pins the values. This test shows that the values are
// those that the specification defines, so that a second reader written from
// the specification opens the archive.
func TestKeyScheduleMatchesSpec(t *testing.T) {
	k := mustDerive(t, "correct horse battery staple")
	dk := k.dataKey

	for _, tc := range []struct {
		name string
		got  []byte
		want []byte
	}{
		{"content key", k.ContentKey(), specKey(t, dk, nil, "eictar/v1/content", testUUID, nil)},
		{"index auth key", k.IndexAuthKey(), specKey(t, dk, nil, "eictar/v1/index-auth", testUUID, nil)},
		{"member key", must(k.MemberKey(testSalt)), specKey(t, dk, testSalt, "eictar/v1/member", testUUID, nil)},
		{"dictionary key", must(k.DictKey(testSalt)), specKey(t, dk, testSalt, "eictar/v1/dict", testUUID, nil)},
	} {
		if !bytes.Equal(tc.got, tc.want) {
			t.Errorf("%s: got %x, the specification gives %x", tc.name, tc.got, tc.want)
		}
	}

	authKey := k.IndexAuthKey()
	index := []byte("an index, as it is on disk")
	for _, gen := range specGenerations {
		if got, want := k.IndexKey(gen), specKey(t, dk, nil, "eictar/v1/index", testUUID, u64le(gen)); !bytes.Equal(got, want) {
			t.Errorf("index key, generation %#x: got %x, the specification gives %x", gen, got, want)
		}

		// digest = BLAKE3-256(archive_uuid || u64le(generation) || index),
		// keyed with authK, or with no key in a plain archive.
		for _, key := range [][]byte{authKey, nil} {
			h := blake3.New(32, key)
			h.Write(testUUID[:])
			h.Write(u64le(gen))
			h.Write(index)
			got := IndexDigest(key, testUUID, gen, index)
			if want := h.Sum(nil); !bytes.Equal(got[:], want) {
				t.Errorf("index digest, generation %#x, keyed %v: got %x, the specification gives %x",
					gen, key != nil, got, want)
			}
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// TestKeyScheduleVectorsHighGeneration pins the index key and the index
// digest at a generation whose eight bytes all differ. The vectors of
// TestKeyScheduleVectors use generation 1, which does not fix the order of
// the other seven bytes.
func TestKeyScheduleVectorsHighGeneration(t *testing.T) {
	k := mustDerive(t, "correct horse battery staple")
	const gen = 0x0102030405060708
	digest := IndexDigest(k.IndexAuthKey(), testUUID, gen, []byte("vector index"))
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"index key, generation 0x0102030405060708", k.IndexKey(gen), indexKeyHighGenVector},
		{"keyed index digest, generation 0x0102030405060708", digest[:], indexDigestHighGenVector},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s changed:\n got %s\nwant %s\n"+
				"Every archive written with the old schedule is now unreadable.",
				tc.name, got, tc.want)
		}
	}
}

// The vectors of TestKeyScheduleVectorsHighGeneration. TestKeyScheduleMatchesSpec
// computes the same values from the specification.
const (
	indexKeyHighGenVector    = "197be317a4668993cd7eecef1e7c3664a60574cfba1192a22d99060fba49f701"
	indexDigestHighGenVector = "3ade64db74d43f5dd38b4a6c5cdaebec3dacfc03b0e5d761a2361440d6c36173"
)

// TestShortInputsAreRefused: a sealed index or a wrapped key comes from the
// archive, and can be of any length. A length too short to hold a nonce must
// give an error, not a panic.
func TestShortInputsAreRefused(t *testing.T) {
	key := make([]byte, 32)
	for _, n := range []int{0, 1, 23, 24, 39} {
		if _, err := OpenIndex(key, 1, make([]byte, n)); !errors.Is(err, ErrAuthentication) {
			t.Errorf("a sealed index of %d bytes: got %v, want ErrAuthentication", n, err)
		}
	}
	for _, n := range []int{0, 10, 23, 24, WrappedKeySize - 1, WrappedKeySize + 1} {
		if _, err := UnwrapKey(key, testUUID, make([]byte, n)); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("a wrapped key of %d bytes: got %v, want ErrWrongPassphrase", n, err)
		}
	}

	// The shortest sealed index is that of an empty plaintext: the nonce and
	// the tag. It must open.
	sealed, err := SealIndex(key, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 24+Overhead {
		t.Fatalf("an empty index sealed to %d bytes", len(sealed))
	}
	if got, err := OpenIndex(key, 1, sealed); err != nil || len(got) != 0 {
		t.Errorf("the empty index: %q, %v", got, err)
	}
}

// TestKeyLengthsAreChecked: a salt or a data key of the wrong length is an
// error, and never a key made from other bytes.
func TestKeyLengthsAreChecked(t *testing.T) {
	for _, n := range []int{0, SaltSize - 1, SaltSize + 1} {
		if _, err := DeriveKEK([]byte("p"), make([]byte, n), fastKDF); err == nil {
			t.Errorf("DeriveKEK took a %d-byte salt", n)
		}
	}
	for _, n := range []int{0, DataKeySize - 1, DataKeySize + 1} {
		if _, err := NewKeys(make([]byte, n), testUUID); err == nil {
			t.Errorf("NewKeys took a %d-byte data key", n)
		}
		if _, err := WrapKey(make([]byte, KEKSize), testUUID, make([]byte, n)); err == nil {
			t.Errorf("WrapKey took a %d-byte data key", n)
		}
	}
}

// TestBadKeysAndParamsAreErrors: a key of the wrong length for a cipher, a
// sealer that has no cipher, and KDF parameters that are not valid give an
// error. Without the checks, each one is a nil cipher or a panic in Argon2id.
func TestBadKeysAndParamsAreErrors(t *testing.T) {
	short := make([]byte, 31)
	for name, try := range map[string]func() error{
		"member sealer": func() error { _, err := NewMemberSealer(short, 1); return err },
		"seal index":    func() error { _, err := SealIndex(short, 1, []byte("x")); return err },
		"open index":    func() error { _, err := OpenIndex(short, 1, make([]byte, 64)); return err },
		"seal dict":     func() error { _, err := SealDict(short, 1, []byte("x")); return err },
		"open dict":     func() error { _, err := OpenDict(short, 1, make([]byte, 64)); return err },
		"wrap key":      func() error { _, err := WrapKey(short, testUUID, make([]byte, DataKeySize)); return err },
		"unwrap key":    func() error { _, err := UnwrapKey(short, testUUID, make([]byte, WrappedKeySize)); return err },
		"zero sealer, seal": func() error {
			_, err := (&MemberSealer{}).Seal(nil, []byte("x"), 0, true)
			return err
		},
		"zero sealer, open": func() error {
			_, err := (&MemberSealer{}).Open(nil, make([]byte, 32), 0, true)
			return err
		},
	} {
		if err := try(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	bad := KDFParams{Time: 0, Memory: 8 * 1024, Threads: 1}
	if _, err := DeriveKEK([]byte("p"), testSalt, bad); err == nil {
		t.Error("DeriveKEK: zero time accepted")
	}
	if _, err := Unlock([]byte("p"), testSalt, testUUID, bad, make([]byte, WrappedKeySize)); err == nil {
		t.Error("Unlock: zero time accepted")
	}
	k, err := NewKeys(make([]byte, DataKeySize), testUUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Wrap([]byte("p"), bad); err == nil {
		t.Error("Wrap: zero time accepted")
	}
}
