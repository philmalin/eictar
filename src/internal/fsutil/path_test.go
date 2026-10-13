package fsutil

import (
	"errors"
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
			// Whatever comes out must be storable, and so must survive
			// extraction, which refuses any other form.
			if !IsStoredPath(got) {
				t.Errorf("StorePath(%q) = %q, which is not canonical", tc.in, got)
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

// TestIsStoredPathRefusesEscapes is the extraction-hardening test. Every case
// here is what a crafted archive contains when it wants to write outside the
// destination. Extraction refuses each member whose path is not in the
// stored form (checkPath in package archive).
func TestIsStoredPathRefusesEscapes(t *testing.T) {
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
		if IsStoredPath(member) {
			t.Errorf("IsStoredPath(%q) = true, want a refusal", member)
		}
	}
}

// TestStorePathOfTwoSeparators: "//" is the root, as "/" is. The check for
// three separators must not read past the end of a path of two.
func TestStorePathOfTwoSeparators(t *testing.T) {
	if got, stripped, err := StorePath("//"); got != RootPath || !stripped || err != nil {
		t.Errorf(`StorePath("//") = %q, %v, %v; want %q, true, nil`, got, stripped, err, RootPath)
	}
}
