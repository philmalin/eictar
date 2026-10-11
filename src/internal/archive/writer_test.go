package archive

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
)

// Tests of the checks of the Writer.

// encryptedOptions gives the options of an encrypted archive, with real keys.
func encryptedOptions(t *testing.T) Options {
	t.Helper()
	o := Options{Codec: "zstd"}
	e := &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF}
	if err := e.apply(&o); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Keys.Zero)
	return o
}

// emptyDir fails the test if dir holds a file: a refused create leaves none.
func emptyDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Errorf("%s stays behind", e.Name())
	}
}

// TestCreateRefusesBadOptions: options that cannot make an archive are
// refused, and leave no file.
func TestCreateRefusesBadOptions(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mod        func(o *Options)
	}{
		{"an unknown codec", "nonesuch", func(o *Options) { o.Codec = "nonesuch" }},
		{"a short salt", "3-byte salt", func(o *Options) { o.Salt = o.Salt[:3] }},
		{"a short wrapped key", "5-byte wrapped key", func(o *Options) { o.WrappedKey = o.WrappedKey[:5] }},
		{"no KDF parameters", "key derivation", func(o *Options) { o.KDFParams = crypt.KDFParams{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := encryptedOptions(t)
			tc.mod(&o)
			dir := t.TempDir()
			w, err := Create(filepath.Join(dir, "x.ect"), o)
			if err == nil {
				w.Abort()
				t.Fatal("the options were accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("Create = %v, want %q", err, tc.want)
			}
			emptyDir(t, dir)
		})
	}
}

// TestCreateRefusesABadTarget: a directory is not an archive, and a link
// that loops has no target.
func TestCreateRefusesABadTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Join(dir, "d"), Options{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Create over a directory = %v", err)
	}
	if err := os.Symlink("b", filepath.Join(dir, "a")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Join(dir, "a"), Options{}); err == nil || !strings.Contains(err.Error(), "resolving") {
		t.Errorf("Create through a loop = %v", err)
	}
}

// TestCreateRefusesAPlantedLink: -f through a link that the rule of
// fs.protected_symlinks does not follow is refused, and the error names the
// link (doc/Security_Audit.md, finding 4). The rule refuses only a link of
// another user, which only root can make, so the test replaces it.
func TestCreateRefusesAPlantedLink(t *testing.T) {
	saved := mayFollowLink
	t.Cleanup(func() { mayFollowLink = saved })
	mayFollowLink = func(string, fs.FileInfo) bool { return false }

	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.ect")
	link := filepath.Join(dir, "backup.ect")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	w, err := Create(link, Options{})
	if err == nil {
		w.Abort() // on Windows, an open file cannot be removed
	}
	if !errors.Is(err, ErrUnsafeLink) || !strings.HasPrefix(err.Error(), link+":") {
		t.Errorf("Create = %v, want %v for %s", err, ErrUnsafeLink, link)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the target of the link was made: %v", err)
	}
}

// payloadFunc is an io.WriterTo from a function.
type payloadFunc func(w io.Writer) (int64, error)

func (p payloadFunc) WriteTo(w io.Writer) (int64, error) { return p(w) }

// TestAppendMemberChecks: a member with a path that is not in stored form is
// refused, and so is a payload that does not write the member's blob.
func TestAppendMemberChecks(t *testing.T) {
	errPayload := errors.New("payload failed")
	member := func(path string) *format.Member {
		return &format.Member{Path: path, Type: format.TypeReg, Mode: 0o644, Codec: format.NoCodec,
			Size: 10, ChunkSize: 4096, Length: 10, Chunks: []uint32{10},
			Digest: make([]byte, format.DigestSize)}
	}
	full := payloadFunc(func(w io.Writer) (int64, error) {
		n, err := w.Write(make([]byte, 10))
		return int64(n), err
	})
	for _, tc := range []struct {
		name    string
		m       *format.Member
		payload io.WriterTo
		want    error
		text    string
	}{
		{"a path that goes up", member("../x"), full, fsutil.ErrUnsafePath, ""},
		{"a short payload", member("short"), payloadFunc(func(w io.Writer) (int64, error) {
			n, err := w.Write(make([]byte, 9))
			return int64(n), err
		}), nil, "wrote 9 bytes, expected 10"},
		{"a payload that fails", member("fails"), payloadFunc(func(w io.Writer) (int64, error) {
			n, _ := w.Write(make([]byte, 10))
			return int64(n), errPayload
		}), errPayload, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := Create(filepath.Join(t.TempDir(), "x.ect"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Abort()
			err = w.AppendMember(tc.m, tc.payload)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
				t.Errorf("AppendMember = %v, want %v %q", err, tc.want, tc.text)
			}
		})
	}
}

// TestEmptyFilesAreNotShared: an empty file has no blob, so there is nothing
// to share, and each empty file stays a member of its own.
func TestEmptyFilesAreNotShared(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/empty1", 0o644, "")
	tree.Text("t/empty2", 0o644, "")
	// Files of holes only: a size, but an empty payload.
	tree.Sparse("t/holes1", 0o644, 1<<20)
	tree.Sparse("t/holes2", 0o644, 1<<20)
	path := mkArchive(t, tree, false, "t")
	check := func(after string) {
		t.Helper()
		r, err := Open(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		for _, m := range r.index.Members {
			if m.Data != 0 && m.PayloadSize() == 0 {
				t.Errorf("after %s: %s shares the content of member %d", after, m.Path, m.Data)
			}
		}
	}
	check("a create")
	// A recompress gives each member its payload again, the empty ones too.
	if _, err := CompactArchive(CompactConfig{Archive: path, Recompress: &RecompressConfig{Codec: "zstd"}}); err != nil {
		t.Fatal(err)
	}
	check("a recompress")
}

// TestCloseTwice: the second Close does nothing, and the archive stays as the
// first one wrote it.
func TestCloseTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.ect")
	w, err := Create(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	if _, err := Info(path, OpenOptions{}); err != nil {
		t.Errorf("after two closes: %v", err)
	}
}

// TestNoOpAppendKeepsTheTimes: an append that is given up before it wrote
// anything leaves the archive alone, its modification time included.
func TestNoOpAppendKeepsTheTimes(t *testing.T) {
	path := mkArchive(t, mutTree(t), false, "t")
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	w, err := OpenAppend(path, Options{}, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if fi := mustStat(t, path); !fi.ModTime().Equal(old) {
		t.Errorf("modification time %v, want %v", fi.ModTime(), old)
	}
}

// TestOpenAppendWithAnUnknownCodec: the codec is refused, and the archive is
// not left locked.
func TestOpenAppendWithAnUnknownCodec(t *testing.T) {
	path := mkArchive(t, mutTree(t), false, "t")
	if w, err := OpenAppend(path, Options{Codec: "nonesuch"}, OpenOptions{}); err == nil {
		w.Abort()
		t.Fatal("the codec was accepted")
	}
	w, err := OpenAppend(path, Options{}, OpenOptions{})
	if err != nil {
		t.Fatalf("after the refused append: %v", err)
	}
	w.Abort()
}

// closeCountingEncoder counts the calls to Close.
type closeCountingEncoder struct {
	codec.Encoder
	closed int
}

func (c *closeCountingEncoder) Close() error { c.closed++; return nil }

// TestAbortClosesTheEncoder: Abort releases the encoder, which can hold much
// memory, once.
func TestAbortClosesTheEncoder(t *testing.T) {
	w, err := Create(filepath.Join(t.TempDir(), "x.ect"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	enc := &closeCountingEncoder{Encoder: w.enc}
	w.enc = enc
	w.Abort()
	w.Abort()
	if enc.closed != 1 {
		t.Errorf("the encoder was closed %d times, want 1", enc.closed)
	}
}
