package fsutil

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePath(t *testing.T) {
	for _, tc := range []struct {
		in           string
		want         string
		wantStripped bool
	}{
		{"file.txt", "file.txt", false},
		{"dir/file.txt", "dir/file.txt", false},
		{"./file.txt", "file.txt", false},
		{"dir//file.txt", "dir/file.txt", false},
		{"dir/./file.txt", "dir/file.txt", false},
		{"dir/sub/../file.txt", "dir/file.txt", false},

		// The convention: a leading slash is removed, so an absolute path
		// unpacks under the destination rather than over the system.
		{"/etc/passwd", "etc/passwd", true},
		{"///etc//passwd", "etc/passwd", true},
		{"/", RootPath, true},

		// Leading ".." is removed for the same reason.
		{"../sibling", "sibling", true},
		{"../../far/away", "far/away", true},
		{"..", RootPath, true},
		{"/../etc/passwd", "etc/passwd", true},
		{"dir/../../escape", "escape", true},

		// Interior "..", already collapsed by Clean, is not an escape.
		{"a/b/../c", "a/c", false},

		{".", RootPath, false},

		// Odd but legal names survive untouched.
		{"odd name with spaces.txt", "odd name with spaces.txt", false},
		{"new\nline.txt", "new\nline.txt", false},
		{"caf\xe9.txt", "caf\xe9.txt", false}, // Latin-1, not UTF-8
		{"-leading-dash", "-leading-dash", false},
		{"...", "...", false},
		{"a/...b", "a/...b", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, stripped, err := StorePath(tc.in)
			if err != nil {
				t.Fatalf("StorePath(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("StorePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if stripped != tc.wantStripped {
				t.Errorf("StorePath(%q) stripped = %v, want %v", tc.in, stripped, tc.wantStripped)
			}
			// Whatever comes out must be storable and must survive extraction.
			if !IsStoredPath(got) {
				t.Errorf("StorePath(%q) = %q, which is not canonical", tc.in, got)
			}
			if _, err := SafeJoin("/dest", got); err != nil {
				t.Errorf("StorePath(%q) = %q, which SafeJoin rejects: %v", tc.in, got, err)
			}
		})
	}
}

func TestStorePathRejectsEmpty(t *testing.T) {
	if _, _, err := StorePath(""); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("error = %v, want ErrUnsafePath", err)
	}
}

// TestStorePathIsIdempotent matters because an append re-normalises paths that
// may already have been normalised.
func TestStorePathIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"/etc/passwd", "../x", "a/b/c", "./a", "/", "..",
	} {
		once, _, err := StorePath(in)
		if err != nil {
			t.Fatalf("StorePath(%q): %v", in, err)
		}
		twice, stripped, err := StorePath(once)
		if err != nil {
			t.Fatalf("StorePath(%q): %v", once, err)
		}
		if twice != once {
			t.Errorf("StorePath is not idempotent: %q -> %q -> %q", in, once, twice)
		}
		if stripped {
			t.Errorf("re-normalising %q reported stripping", once)
		}
	}
}

func TestIsStoredPath(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"a", true},
		{"a/b", true},
		{".", true},
		{"a/.../b", true},
		{"", false},
		{"/a", false},
		{"a/", false},
		{"a//b", false},
		{"..", false},
		{"../a", false},
		{"a/../b", false},
		{"a/./b", false},
		{"./a", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := IsStoredPath(tc.in); got != tc.want {
				t.Errorf("IsStoredPath(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSafeJoin(t *testing.T) {
	dest := filepath.FromSlash("/tmp/dest")

	for _, tc := range []struct {
		member string
		want   string
	}{
		{"file.txt", filepath.Join(dest, "file.txt")},
		{"a/b/c.txt", filepath.Join(dest, "a", "b", "c.txt")},
		{".", dest},
		{"odd name.txt", filepath.Join(dest, "odd name.txt")},
	} {
		t.Run(tc.member, func(t *testing.T) {
			got, err := SafeJoin(dest, tc.member)
			if err != nil {
				t.Fatalf("SafeJoin(%q, %q): %v", dest, tc.member, err)
			}
			if got != tc.want {
				t.Errorf("SafeJoin = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSafeJoinRefusesEscapes is the extraction-hardening test. Every case here is what a crafted archive contains when it wants to write outside
// the destination.
func TestSafeJoinRefusesEscapes(t *testing.T) {
	dest := filepath.FromSlash("/tmp/dest")

	for _, member := range []string{
		"",
		"/etc/passwd",
		"/",
		"..",
		"../escape",
		"../../../../etc/passwd",
		"a/../../escape",
		"a/../..",
		"./a",   // not canonical: the writer never emits this
		"a//b",  // not canonical
		"a/",    // not canonical
		"a/./b", // not canonical
	} {
		t.Run(member, func(t *testing.T) {
			got, err := SafeJoin(dest, member)
			if err == nil {
				t.Fatalf("SafeJoin(%q, %q) = %q, want a refusal", dest, member, got)
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Errorf("error = %v, want ErrUnsafePath", err)
			}
		})
	}
}

// TestSafeJoinStaysUnderDestination is the property the individual cases are
// examples of: whatever comes back is under the destination, always.
func TestSafeJoinStaysUnderDestination(t *testing.T) {
	dest := filepath.FromSlash("/tmp/dest")

	for _, member := range []string{
		"a", "a/b", "a/b/c", ".", "deep/" + strings.Repeat("x/", 40) + "leaf",
	} {
		got, err := SafeJoin(dest, member)
		if err != nil {
			t.Fatalf("SafeJoin(%q, %q): %v", dest, member, err)
		}
		if got != dest && !strings.HasPrefix(got, dest+string(filepath.Separator)) {
			t.Errorf("SafeJoin(%q, %q) = %q, which is outside the destination", dest, member, got)
		}
	}
}

// TestSafeJoinRelativeDestination covers -d with a relative directory, which
// is what a user types most of the time.
func TestSafeJoinRelativeDestination(t *testing.T) {
	got, err := SafeJoin("out", "a/b.txt")
	if err != nil {
		t.Fatalf("SafeJoin: %v", err)
	}
	if want := filepath.Join("out", "a", "b.txt"); got != want {
		t.Errorf("SafeJoin = %q, want %q", got, want)
	}
	if _, err := SafeJoin("out", "../b.txt"); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("error = %v, want ErrUnsafePath", err)
	}
}
