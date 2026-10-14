package compare

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/tools/ectread/ect"
)

const goldenDir = "../../../src/internal/archive/testdata/golden"

// listingOf makes the listing that eictar -t --json gives for a, from the
// fields of doc/design.md 10.9.
func listingOf(a *ect.Archive) []map[string]any {
	var out []map[string]any
	for _, m := range a.Live() {
		j := map[string]any{"path": m.Path, "type": m.Type, "size": m.Size, "mode": m.Mode,
			"mtime": time.Unix(0, m.Mtime).UTC().Format(time.RFC3339Nano)}
		switch m.Type {
		case "symlink":
			j["target"] = m.Link
		case "hardlink":
			j["hardlink_to"] = a.ByID(m.Hardlink).Path
		case "reg":
			j["digest"] = hex.EncodeToString(m.Digest)
			if m.Data != 0 {
				j["same_as"] = a.ByID(m.Data).Path
				j["stored_size"] = 0
				if a.ByID(m.Data).Dead {
					j["same_as_deleted"] = true
				}
				break
			}
			codec := "none"
			if m.Codec >= 0 {
				codec = a.Codecs[m.Codec].Name
			}
			j["codec"] = map[string]any{"name": codec}
			j["stored_size"] = m.Len
			j["chunks"] = len(m.Chunks)
			j["encrypted"] = a.Encrypted && m.HasBlob
		}
		out = append(out, j)
	}
	return out
}

func open(t *testing.T, name string, pass string) *ect.Archive {
	t.Helper()
	var opt ect.Options
	if pass != "" {
		opt.Passphrase = []byte(pass)
	}
	a, err := ect.Open(filepath.Join(goldenDir, name), opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func TestListing(t *testing.T) {
	for _, g := range []struct{ name, pass string }{{"plain.ect", ""}, {"shared.ect", ""}, {"dict.ect", "golden"}} {
		a := open(t, g.name, g.pass)
		b, _ := json.Marshal(listingOf(a))
		if err := Listing(a, b); err != nil {
			t.Errorf("%s: %v", g.name, err)
		}
	}
	a := open(t, "plain.ect", "")
	byPath := func(l []map[string]any, p string) map[string]any {
		for _, j := range l {
			if j["path"] == p {
				return j
			}
		}
		t.Fatalf("no %s", p)
		return nil
	}
	for _, tc := range []struct {
		name   string
		change func(l []map[string]any) []map[string]any
		want   string
	}{
		{"a field that is not known", func(l []map[string]any) []map[string]any { l[0]["colour"] = "red"; return l }, "unknown field"},
		{"a missing member", func(l []map[string]any) []map[string]any { return l[1:] }, "does not list"},
		{"an extra member", func(l []map[string]any) []map[string]any { return append(l, map[string]any{"path": "x"}) }, "not a live member"},
		{"a member twice", func(l []map[string]any) []map[string]any { return append(l, l[0]) }, "lists it twice"},
		{"type", func(l []map[string]any) []map[string]any { byPath(l, "g")["type"] = "reg"; return l }, "type"},
		{"size", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["size"] = 20; return l }, "size"},
		{"mode", func(l []map[string]any) []map[string]any { byPath(l, "g")["mode"] = 0o700; return l }, "mode"},
		{"mtime", func(l []map[string]any) []map[string]any {
			byPath(l, "g")["mtime"] = "2026-01-02T03:04:05.000000007Z"
			return l
		}, "mtime"},
		{"target", func(l []map[string]any) []map[string]any { byPath(l, "g/link")["target"] = "hard.txt"; return l }, "target"},
		{"no target", func(l []map[string]any) []map[string]any { delete(byPath(l, "g/link"), "target"); return l }, "target"},
		{"hardlink_to", func(l []map[string]any) []map[string]any {
			byPath(l, "g/keep.txt")["hardlink_to"] = "g/new.txt"
			return l
		}, "hardlink_to"},
		{"same_as", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["same_as"] = "g/edit.txt"; return l }, "same_as"},
		{"owner", func(l []map[string]any) []map[string]any {
			byPath(l, "g")["uid"] = 0
			byPath(l, "g")["gid"] = 0
			return l
		}, "uid and gid"},
		{"uname", func(l []map[string]any) []map[string]any { byPath(l, "g")["uname"] = "root"; return l }, "uname"},
		{"gname", func(l []map[string]any) []map[string]any { byPath(l, "g")["gname"] = "root"; return l }, "gname"},
		{"rdev", func(l []map[string]any) []map[string]any { byPath(l, "g")["rdev"] = []int{1, 3}; return l }, "rdev"},
		{"sparse", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["sparse"] = true; return l }, "sparse"},
		{"xattrs", func(l []map[string]any) []map[string]any { byPath(l, "g")["xattrs"] = []string{"user.x"}; return l }, "xattrs"},
		{"codec", func(l []map[string]any) []map[string]any {
			byPath(l, "g/new.txt")["codec"] = map[string]any{"name": "zstd"}
			return l
		}, "codec"},
		{"stored_size", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["stored_size"] = 3; return l }, "stored_size"},
		{"chunks", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["chunks"] = 3; return l }, "chunks"},
		{"encrypted", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["encrypted"] = true; return l }, "encrypted"},
		{"digest", func(l []map[string]any) []map[string]any { byPath(l, "g/new.txt")["digest"] = "00"; return l }, "digest"},
		{"content of a directory", func(l []map[string]any) []map[string]any { byPath(l, "g")["chunks"] = 0; return l }, "fields of content"},
	} {
		b, _ := json.Marshal(tc.change(listingOf(a)))
		if err := Listing(a, b); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error with %q", tc.name, err, tc.want)
		}
	}
}

func TestTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the golden archive has a symbolic link")
	}
	a := open(t, "plain.ect", "")
	for _, tc := range []struct {
		name   string
		change func(root string) error
		want   string
	}{
		{"no change", func(root string) error { return nil }, ""},
		{"content", func(root string) error {
			return os.WriteFile(filepath.Join(root, "g/new.txt"), []byte("the same length, not same"), 0o644)
		}, "content differs"},
		{"a missing file", func(root string) error { return os.Remove(filepath.Join(root, "g/new.txt")) }, "not extracted"},
		{"an extra file", func(root string) error { return os.WriteFile(filepath.Join(root, "g/extra"), nil, 0o644) }, "not a live member"},
		{"an extra directory", func(root string) error { return os.Mkdir(filepath.Join(root, "x"), 0o755) }, "not a live member"},
		{"a link target", func(root string) error {
			p := filepath.Join(root, "g/link")
			os.Remove(p)
			return os.Symlink("hard.txt", p)
		}, "links to"},
		{"a hardlink that is a copy", func(root string) error {
			p := filepath.Join(root, "g/keep.txt")
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			os.Remove(p)
			return os.WriteFile(p, b, 0o644)
		}, "not one file with"},
		{"a file for a directory", func(root string) error {
			p := filepath.Join(root, "g/sub")
			os.RemoveAll(p)
			return os.WriteFile(p, nil, 0o644)
		}, "not a directory"},
		{"a directory for a file", func(root string) error {
			p := filepath.Join(root, "g/new.txt")
			os.Remove(p)
			return os.Mkdir(p, 0o755)
		}, "not a file"},
	} {
		root := filepath.Join(t.TempDir(), "out")
		if err := ect.Extract(a, root, io.Discard); err != nil {
			t.Fatal(err)
		}
		if err := tc.change(root); err != nil {
			t.Fatal(err)
		}
		err := Tree(a, root)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want an error with %q", tc.name, err, tc.want)
		}
	}
}
