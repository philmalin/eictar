package crypt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

var (
	testSalt = bytes.Repeat([]byte{0x01}, SaltSize)
	testUUID = [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	// Cheap parameters: these tests exercise the schedule, not its cost.
	fastKDF = KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
)

func mustDerive(t *testing.T, passphrase string) *Keys {
	t.Helper()
	k, err := Derive([]byte(passphrase), testSalt, testUUID, fastKDF)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	return k
}

// TestKeyScheduleVectors pins every derived value and every sealed output to
// fixed bytes.
//
// This is the most important test in the package and it will look like
// busywork until the day it fires. Every key an archive was ever written with
// comes out of this schedule: change a dependency, an info string, a parameter
// or the order of an HKDF input, and every existing archive becomes
// undecryptable - silently, with every other test still passing, because
// encrypt-then-decrypt round trips agree with themselves whatever the keys
// are. These vectors are the only thing that notices.
//
// A failure here is never "update the vector". It means the format changed and
// old archives no longer open.
func TestKeyScheduleVectors(t *testing.T) {
	k := mustDerive(t, "correct horse battery staple")

	memberKey, err := k.MemberKey(testSalt)
	if err != nil {
		t.Fatalf("MemberKey: %v", err)
	}
	sealer, err := NewMemberSealer(memberKey, 7)
	if err != nil {
		t.Fatalf("NewMemberSealer: %v", err)
	}
	sealedChunk, err := sealer.Seal(nil, []byte("vector plaintext"), 3, true)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var indexNonce [24]byte
	indexNonce[23] = 1
	sealedIndex, err := sealIndexWithNonce(k.IndexKey(1), 1, indexNonce, []byte("vector index"))
	if err != nil {
		t.Fatalf("SealIndex: %v", err)
	}
	digest := IndexDigest(k.IndexAuthKey(), testUUID, 1, []byte("vector index"))

	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"master key", k.master,
			"410e70a43437e782f539589bddec13a5e7a5513ded7400de04b6b8b2ef71a2e1"},
		{"check value", k.Check(),
			"867d1cda13093bc1effc38ab69f824ad5d1543845e02180353dbccb8209250d3"},
		{"index auth key", k.IndexAuthKey(),
			"6ba20bc54a8983ee129dec7f0db63f11f40a52576d4dda88c8de4ca52d6c2497"},
		{"index key, generation 1", k.IndexKey(1),
			"7af954f9a76ae2289cd7afe916537afa2800c76bbe3b72f96996098535460674"},
		{"member key", memberKey,
			"dd7eb76dbeff619bc2027a1477eb242d53ce7d169ba4259a810385406f958b6b"},
		{"sealed chunk", sealedChunk,
			"d8ed4174b1c8d4b8ca2107fc7c6b9a27efda3268d750864a69a4e853573770ec"},
		{"sealed index", sealedIndex,
			"000000000000000000000000000000000000000000000001" +
				"a27ac7f6ea48fd1138b0be74c0c0363f22a9d813948aa4b853f21218"},
		{"keyed index digest", digest[:],
			"51a0e9b88f6251abfd4c95b3d5324128128e9a08449ea476fd129275d4204bf5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hex.EncodeToString(tc.got); got != tc.want {
				t.Errorf("%s changed:\n got %s\nwant %s\n"+
					"Every archive written with the old schedule is now unreadable.",
					tc.name, got, tc.want)
			}
		})
	}
}

// TestKDFParamsAreLoadBearing: the vectors above are for fastKDF. A change to
// the parameters an archive records must change the key, or the parameters
// would be decoration.
func TestKDFParamsAreLoadBearing(t *testing.T) {
	base := mustDerive(t, "passphrase")

	for _, p := range []KDFParams{
		{Time: 2, Memory: 8 * 1024, Threads: 1},
		{Time: 1, Memory: 16 * 1024, Threads: 1},
		{Time: 1, Memory: 8 * 1024, Threads: 2},
	} {
		other, err := Derive([]byte("passphrase"), testSalt, testUUID, p)
		if err != nil {
			t.Fatalf("Derive(%+v): %v", p, err)
		}
		if bytes.Equal(base.master, other.master) {
			t.Errorf("%+v produced the same key as %+v", p, fastKDF)
		}
	}
}

// TestSubkeysAreDistinct: every purpose must get a different key, or a value
// derived for one job could be used for another.
func TestSubkeysAreDistinct(t *testing.T) {
	k := mustDerive(t, "passphrase")

	memberKey, err := k.MemberKey(testSalt)
	if err != nil {
		t.Fatalf("MemberKey: %v", err)
	}

	keys := map[string][]byte{
		"master":     k.master,
		"check":      k.Check(),
		"index-auth": k.IndexAuthKey(),
		"index-1":    k.IndexKey(1),
		"index-2":    k.IndexKey(2),
		"member":     memberKey,
	}
	for aName, a := range keys {
		for bName, b := range keys {
			if aName >= bName {
				continue
			}
			if bytes.Equal(a, b) {
				t.Errorf("%s and %s derived the same key", aName, bName)
			}
		}
	}
}

func TestMemberKeysDifferPerSalt(t *testing.T) {
	k := mustDerive(t, "passphrase")

	a, err := k.MemberKey(bytes.Repeat([]byte{1}, SaltSize))
	if err != nil {
		t.Fatalf("MemberKey: %v", err)
	}
	b, err := k.MemberKey(bytes.Repeat([]byte{2}, SaltSize))
	if err != nil {
		t.Fatalf("MemberKey: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two salts produced the same member key")
	}
	if _, err := k.MemberKey([]byte{1, 2, 3}); err == nil {
		t.Error("a short salt was accepted")
	}
}

// TestKeysAreBoundToTheArchive: the same passphrase and salt in a different
// archive must not give the same keys, or an index could be lifted between
// archives.
func TestKeysAreBoundToTheArchive(t *testing.T) {
	a, err := Derive([]byte("same"), testSalt, [16]byte{1}, fastKDF)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	b, err := Derive([]byte("same"), testSalt, [16]byte{2}, fastKDF)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if bytes.Equal(a.Check(), b.Check()) {
		t.Error("two archives with different ids derived the same check value")
	}
	if bytes.Equal(a.IndexAuthKey(), b.IndexAuthKey()) {
		t.Error("two archives with different ids derived the same index key")
	}
}

func TestCheckRejectsWrongPassphrase(t *testing.T) {
	right := mustDerive(t, "right")
	wrong := mustDerive(t, "wrong")

	if err := right.VerifyCheck(right.Check()); err != nil {
		t.Errorf("the correct passphrase was rejected: %v", err)
	}
	if err := wrong.VerifyCheck(right.Check()); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("error = %v, want ErrWrongPassphrase", err)
	}
	// An empty or short stored value must not pass.
	if err := right.VerifyCheck(nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("error = %v, want ErrWrongPassphrase", err)
	}
}

func TestKDFParamsValidate(t *testing.T) {
	if err := DefaultKDFParams.Validate(); err != nil {
		t.Errorf("the defaults are invalid: %v", err)
	}
	for _, p := range []KDFParams{
		{Time: 0, Memory: 65536, Threads: 4},
		{Time: 3, Memory: 65536, Threads: 0},
		{Time: 3, Memory: 8, Threads: 4}, // below 8 KiB per lane
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%+v was accepted", p)
		}
	}
}

// TestChunkSealRoundTrip and the tamper tests below are the integrity story
// for member content.
func TestChunkSealRoundTrip(t *testing.T) {
	k := mustDerive(t, "passphrase")
	key, err := k.MemberKey(testSalt)
	if err != nil {
		t.Fatalf("MemberKey: %v", err)
	}
	s, err := NewMemberSealer(key, 7)
	if err != nil {
		t.Fatalf("NewMemberSealer: %v", err)
	}

	for _, plain := range [][]byte{
		{},
		[]byte("one chunk"),
		bytes.Repeat([]byte("x"), 1<<16),
	} {
		sealed, err := s.Seal(nil, plain, 0, true)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if len(sealed) != len(plain)+Overhead {
			t.Errorf("sealed %d bytes from %d, want an overhead of %d",
				len(sealed), len(plain), Overhead)
		}

		got, err := s.Open(nil, sealed, 0, true)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Error("the chunk did not survive the round trip")
		}
	}
}

// TestChunkTamperIsCaught covers every way a chunk can be moved or edited.
func TestChunkTamperIsCaught(t *testing.T) {
	k := mustDerive(t, "passphrase")
	key, _ := k.MemberKey(testSalt)
	s, _ := NewMemberSealer(key, 7)

	plain := []byte("the quick brown fox")
	sealed, err := s.Seal(nil, plain, 3, false)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	otherKey, _ := k.MemberKey(bytes.Repeat([]byte{9}, SaltSize))
	otherMember, _ := NewMemberSealer(otherKey, 7)
	otherID, _ := NewMemberSealer(key, 8)

	for _, tc := range []struct {
		name string
		open func() ([]byte, error)
	}{
		{"flipped byte in the ciphertext", func() ([]byte, error) {
			bad := bytes.Clone(sealed)
			bad[2] ^= 0xff
			return s.Open(nil, bad, 3, false)
		}},
		{"flipped byte in the tag", func() ([]byte, error) {
			bad := bytes.Clone(sealed)
			bad[len(bad)-1] ^= 0xff
			return s.Open(nil, bad, 3, false)
		}},
		{"truncated", func() ([]byte, error) {
			return s.Open(nil, sealed[:len(sealed)-1], 3, false)
		}},
		{"moved to another chunk index", func() ([]byte, error) {
			return s.Open(nil, sealed, 4, false)
		}},
		{"claimed as the final chunk", func() ([]byte, error) {
			return s.Open(nil, sealed, 3, true)
		}},
		{"moved to another member id", func() ([]byte, error) {
			return otherID.Open(nil, sealed, 3, false)
		}},
		{"opened with another member's key", func() ([]byte, error) {
			return otherMember.Open(nil, sealed, 3, false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.open(); err == nil {
				t.Errorf("tampering was accepted, returning %q", got)
			}
		})
	}
}

func TestIndexSealRoundTrip(t *testing.T) {
	k := mustDerive(t, "passphrase")
	key := k.IndexKey(5)
	plain := []byte("an index, pretend it is CBOR")

	sealed, err := SealIndex(key, 5, plain)
	if err != nil {
		t.Fatalf("SealIndex: %v", err)
	}
	got, err := OpenIndex(key, 5, sealed)
	if err != nil {
		t.Fatalf("OpenIndex: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("the index did not survive the round trip")
	}

	// Replayed into another generation, it must not open.
	if _, err := OpenIndex(k.IndexKey(6), 6, sealed); err == nil {
		t.Error("an index from generation 5 opened as generation 6")
	}
	bad := bytes.Clone(sealed)
	bad[0] ^= 0xff
	if _, err := OpenIndex(key, 5, bad); err == nil {
		t.Error("a tampered index opened")
	}
}

// TestIndexDigestIsKeyed is the point of doc/design.md 6.4: with a key, an
// attacker who cannot read any content still cannot rewrite the metadata.
func TestIndexDigestIsKeyed(t *testing.T) {
	k := mustDerive(t, "passphrase")
	indexBytes := []byte("member paths and modes live here")

	keyed := IndexDigest(k.IndexAuthKey(), testUUID, 1, indexBytes)
	plainDigest := IndexDigest(nil, testUUID, 1, indexBytes)
	if keyed == plainDigest {
		t.Fatal("the keyed digest matches the unkeyed one")
	}

	// An attacker without the key cannot produce the keyed value.
	attacker := IndexDigest(nil, testUUID, 1, []byte("rewritten metadata"))
	if attacker == keyed {
		t.Fatal("an unkeyed digest matched the keyed one")
	}

	// Bound to the archive and the generation.
	if IndexDigest(k.IndexAuthKey(), [16]byte{9}, 1, indexBytes) == keyed {
		t.Error("the digest is not bound to the archive id")
	}
	if IndexDigest(k.IndexAuthKey(), testUUID, 2, indexBytes) == keyed {
		t.Error("the digest is not bound to the generation")
	}
	// And to the content.
	if IndexDigest(k.IndexAuthKey(), testUUID, 1, []byte("edited")) == keyed {
		t.Error("the digest is not bound to the index bytes")
	}
}

func TestZeroWipesTheMaster(t *testing.T) {
	k := mustDerive(t, "passphrase")
	k.Zero()
	for _, b := range k.master {
		if b != 0 {
			t.Fatal("Zero left key material behind")
		}
	}
}

// TestIndexDigestDoesNotFailOpen: a key of the wrong length used to fall back
// silently to the unkeyed hash, removing the only protection the metadata has.
func TestIndexDigestDoesNotFailOpen(t *testing.T) {
	for _, key := range [][]byte{{}, make([]byte, 16), make([]byte, 31), make([]byte, 33)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("a %d-byte key was accepted", len(key))
				}
			}()
			IndexDigest(key, testUUID, 1, []byte("x"))
		}()
	}
	// nil and 32 bytes are the two meaningful inputs.
	IndexDigest(nil, testUUID, 1, []byte("x"))
	IndexDigest(make([]byte, 32), testUUID, 1, []byte("x"))
}

// TestIndexNonceIsFresh: two indexes sealed for the same generation must not
// share a nonce. An archive copied and appended to on both sides does exactly
// that, and a shared nonce exposes the XOR of the two indexes.
func TestIndexNonceIsFresh(t *testing.T) {
	k := mustDerive(t, "passphrase")
	key := k.IndexKey(3)
	a, err := SealIndex(key, 3, []byte("index one"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealIndex(key, 3, []byte("index two"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[:24], b[:24]) {
		t.Fatal("two index seals used the same nonce")
	}
	for _, sealed := range [][]byte{a, b} {
		if _, err := OpenIndex(key, 3, sealed); err != nil {
			t.Fatalf("OpenIndex: %v", err)
		}
	}
	if _, err := OpenIndex(key, 3, a[:30]); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("short sealed index: got %v, want ErrAuthentication", err)
	}
}
