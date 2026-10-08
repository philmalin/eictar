//go:build (unix && !aix) || windows

package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestSecondWriterIsRefused: while one writer holds an archive, every other
// kind of writer stops at once with ErrLocked, and the archive is unchanged.
// Readers are not affected (doc/design.md 9.6).
func TestSecondWriterIsRefused(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t/a.txt")
	before := readAll(t, archive)

	first, err := OpenAppend(archive, Options{}, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for name, try := range map[string]func() error{
		"append": func() error { _, err := appendTo(t, archive, tree, false, nil, "t/b.txt"); return err },
		"delete": func() error {
			_, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/a.txt"}})
			return err
		},
		"compact": func() error { _, err := CompactArchive(CompactConfig{Archive: archive}); return err },
		"repair":  func() error { return repairOf(archive) },
		"create": func() error {
			_, err := CreateArchive(CreateConfig{Archive: archive, Paths: []string{"t"}, BaseDir: tree.Root})
			return err
		},
	} {
		if err := try(); !errors.Is(err, ErrLocked) {
			t.Errorf("%s while another writer runs: got %v, want ErrLocked", name, err)
		}
	}
	if _, _, gen := state(t, archive, false); gen != 1 {
		t.Errorf("a reader saw generation %d", gen)
	}

	first.Abort()
	if !bytes.Equal(readAll(t, archive), before) {
		t.Fatal("the refused writers changed the archive")
	}
	if _, err := appendTo(t, archive, tree, false, nil, "t/b.txt"); err != nil {
		t.Errorf("the lock outlived its writer: %v", err)
	}
}

// repairOf forces the scan: a repair of an intact archive returns before it
// takes the lock.
func repairOf(archive string) error {
	b, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	f.Write([]byte("junk"))
	f.Close()
	defer os.WriteFile(archive, b, 0o644)
	_, err = RepairArchive(archive, OpenOptions{})
	return err
}

// TestLockOnAReplacedFileIsRefused: a process that opened the path before a
// rename replaced it must not write to the unlinked file.
func TestLockOnAReplacedFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renameOver(filepath.Join(dir, "b"), path); err != nil {
		t.Fatal(err)
	}
	if err := lockArchive(f, path); !errors.Is(err, ErrLocked) {
		t.Errorf("lock on the replaced file: got %v, want ErrLocked", err)
	}
}
