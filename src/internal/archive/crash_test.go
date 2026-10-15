package archive

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

// crashFS is the file system of the archive files (fs.go) with a model of
// what a power loss keeps (doc/testing.md 5, step 3). The operations reach
// the disk as they do in production. Beside them, crashFS keeps the content
// of each file at its last Sync, and the names of the directory at its last
// SyncDir. After each operation that changes a file or a name, it records
// what the path of the archive can hold if the power fails then:
//
//   - the names of the directory are those of the last SyncDir, or the
//     current ones;
//   - the file at that name holds what it held at its last Sync, or what it
//     holds now. When it holds more now, it can also hold the content of the
//     last Sync and half of what came after (a torn write), or all of it
//     but one write since the last Sync, which holds what it held at the
//     last Sync (writes that reach the disk out of order).
//
// Each state is kept once, with the first operation that gives it.
type crashFS struct {
	t   *testing.T
	mu  sync.Mutex
	dir string // the directory of the archive
	// resolved is dir with its links resolved, as the writer resolves it.
	resolved string
	target   string // the base name of the archive
	ops      int
	nextID   int
	cur      map[string]int   // name to file, now
	dur      map[string]int   // name to file, at the last SyncDir
	synced   map[int][]byte   // file to content, at its last Sync
	pending  map[int][]extent // file to the writes since its last Sync
	states   map[[32]byte]crashState
	// renamed means that the operation renamed a file: it commits with a
	// rename, and must never need a repair.
	renamed bool
}

// crashState is one content that the path of the archive can hold after a
// power loss.
type crashState struct {
	absent bool
	data   []byte
	op     int    // the number of the operation
	after  string // the operation after which the power failed
	how    string // how the state was made
}

// newCrashFS starts the model with the files in dir, as if each was synced.
func newCrashFS(t *testing.T, dir, target string) *crashFS {
	fs := &crashFS{t: t, dir: dir, target: target, cur: map[string]int{}, synced: map[int][]byte{}, pending: map[int][]extent{},
		states: map[[32]byte]crashState{}}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs.resolved = resolved
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		fs.nextID++
		fs.cur[e.Name()] = fs.nextID
		fs.synced[fs.nextID] = readAll(t, filepath.Join(dir, e.Name()))
	}
	fs.dur = maps.Clone(fs.cur)
	fs.record("the start")
	return fs
}

// record adds the states that a power loss after op can leave. The caller
// holds fs.mu.
func (fs *crashFS) record(op string) {
	fs.ops++
	after := fmt.Sprintf("%s (operation %d)", op, fs.ops)
	add := func(absent bool, data []byte, how string) {
		key := sha256.Sum256(append([]byte{map[bool]byte{false: 0, true: 1}[absent]}, data...))
		if _, ok := fs.states[key]; !ok {
			fs.states[key] = crashState{absent: absent, data: bytes.Clone(data), op: fs.ops, after: after, how: how}
		}
	}
	for _, names := range []struct {
		how string
		ns  map[string]int
	}{{"synced names", fs.dur}, {"current names", fs.cur}} {
		id, ok := names.ns[fs.target]
		if !ok {
			add(true, nil, names.how)
			continue
		}
		synced := fs.synced[id]
		add(false, synced, names.how+", synced content")
		now, ok := fs.current(id)
		if !ok {
			continue
		}
		add(false, now, names.how+", current content")
		if len(now) > len(synced) && bytes.HasPrefix(now, synced) {
			mid := len(synced) + (len(now)-len(synced))/2
			add(false, now[:mid], names.how+", torn write")
		}
		for i, e := range fs.pending[id] {
			add(false, lose(now, synced, e), fmt.Sprintf("%s, write %d of %d since the sync lost", names.how, i+1, len(fs.pending[id])))
		}
	}
}

// extent is the place of one write in its file.
type extent struct{ off, n int64 }

// lose gives now with the write e lost: its bytes hold what they held at the
// last Sync, or zeros past the end of that content.
func lose(now, synced []byte, e extent) []byte {
	out := bytes.Clone(now)
	for i := e.off; i < e.off+e.n && i < int64(len(out)); i++ {
		out[i] = 0
		if i < int64(len(synced)) {
			out[i] = synced[i]
		}
	}
	return out
}

// current gives what the file id holds now, if a current name names it.
func (fs *crashFS) current(id int) ([]byte, bool) {
	for name, n := range fs.cur {
		if n == id {
			b, err := os.ReadFile(filepath.Join(fs.dir, name))
			if err != nil {
				fs.t.Errorf("crashFS: %v", err)
				return nil, false
			}
			return b, true
		}
	}
	return nil, false
}

// name gives the base name of path, which must be in the directory of the
// archive.
func (fs *crashFS) name(path string) string {
	// The writer resolves the path of the archive, and on Windows that also
	// gives the long form of a short name (RUNNER~1 to runneradmin).
	dir := filepath.Dir(path)
	if dir != filepath.Clean(fs.dir) && dir != fs.resolved {
		fs.t.Errorf("crashFS: %s is not in %s", path, fs.dir)
	}
	return filepath.Base(path)
}

func (fs *crashFS) wrap(f archiveFile, id int) archiveFile {
	return &crashFile{archiveFile: f, fs: fs, id: id}
}

func (fs *crashFS) OpenArchive(path string, flag int) (archiveFile, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, err := osFS{}.OpenArchive(path, flag)
	if err != nil {
		return nil, err
	}
	id, ok := fs.cur[fs.name(path)]
	if !ok {
		fs.t.Errorf("crashFS: %s opened, but the model does not have it", path)
	}
	return fs.wrap(f, id), nil
}

// created adds a new file to the names of now. It is empty at its last Sync.
func (fs *crashFS) created(f archiveFile, err error, op string) (archiveFile, error) {
	if err != nil {
		return nil, err
	}
	fs.nextID++
	fs.cur[fs.name(f.Name())] = fs.nextID
	fs.synced[fs.nextID] = nil
	fs.record(op + " " + filepath.Base(f.Name()))
	return fs.wrap(f, fs.nextID), nil
}

func (fs *crashFS) CreateNew(path string, perm os.FileMode) (archiveFile, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, err := osFS{}.CreateNew(path, perm)
	return fs.created(f, err, "create")
}

func (fs *crashFS) CreateTemp(dir, pattern string) (archiveFile, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f, err := osFS{}.CreateTemp(dir, pattern)
	return fs.created(f, err, "create")
}

func (fs *crashFS) Rename(oldpath, newpath string, replace bool) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := (osFS{}).Rename(oldpath, newpath, replace); err != nil {
		return err
	}
	old, name := fs.name(oldpath), fs.name(newpath)
	fs.cur[name] = fs.cur[old]
	delete(fs.cur, old)
	fs.renamed = true
	fs.record("rename " + old + " to " + name)
	return nil
}

func (fs *crashFS) Remove(path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := (osFS{}).Remove(path); err != nil {
		return err
	}
	delete(fs.cur, fs.name(path))
	fs.record("remove " + filepath.Base(path))
	return nil
}

func (fs *crashFS) SyncDir(dir string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := (osFS{}).SyncDir(dir); err != nil {
		return err
	}
	fs.dur = maps.Clone(fs.cur)
	fs.record("syncdir")
	return nil
}

// crashFile is an archive file of a crashFS.
type crashFile struct {
	archiveFile
	fs *crashFS
	id int
}

func (f *crashFile) Write(p []byte) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	off, err := f.archiveFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	n, err := f.archiveFile.Write(p)
	f.fs.pending[f.id] = append(f.fs.pending[f.id], extent{off, int64(n)})
	f.fs.record(fmt.Sprintf("write of %d bytes to %s", n, filepath.Base(f.Name())))
	return n, err
}

func (f *crashFile) Truncate(size int64) error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	err := f.archiveFile.Truncate(size)
	// A write past the new end is gone, whatever reaches the disk.
	var kept []extent
	for _, e := range f.fs.pending[f.id] {
		if e.off < size {
			e.n = min(e.n, size-e.off)
			kept = append(kept, e)
		}
	}
	f.fs.pending[f.id] = kept
	f.fs.record(fmt.Sprintf("truncate of %s to %d", filepath.Base(f.Name()), size))
	return err
}

func (f *crashFile) Sync() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.archiveFile.Sync(); err != nil {
		return err
	}
	// By its name: the file of a create is open for writing only.
	b, ok := f.fs.current(f.id)
	if !ok {
		f.fs.t.Errorf("crashFS: %s was synced, but no name names it", f.Name())
	}
	f.fs.synced[f.id] = b
	f.fs.pending[f.id] = nil
	f.fs.record("sync of " + filepath.Base(f.Name()))
	return nil
}

// durable gives what the path of the archive holds after a power loss when
// each change is on the disk that a Sync or a SyncDir put there, and no more.
func (fs *crashFS) durable() (absent bool, data []byte) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	id, ok := fs.dur[fs.target]
	if !ok {
		return true, nil
	}
	return false, fs.synced[id]
}

// openState puts a state at a new path, and gives what the archive holds
// there. When the archive is damaged and repair is true, it repairs it first,
// and says so.
func openState(t *testing.T, name string, absent bool, data []byte, opens []OpenOptions, repair bool) (state string, repaired bool, err error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if !absent {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	state, err = archiveState(path, opens)
	if err == nil || !IsDamage(err) || !repair {
		return state, false, err
	}
	for _, o := range opens {
		if _, err = RepairArchive(path, o); err == nil {
			break
		}
	}
	if err != nil {
		return "", true, fmt.Errorf("the archive is damaged, and repair fails: %w", err)
	}
	state, err = archiveState(path, opens)
	return state, true, err
}

// TestPowerLossLeavesTheOldOrTheNewArchive runs each operation that writes an
// archive, and checks each state that a power loss at any point can leave at
// the path of the archive (crashFS):
//
//   - The archive holds its old state or its new state. An operation that
//     writes in place, as an append does, can need --repair to give one of
//     them back. An operation that commits with a rename must not.
//   - When the operation has reported success, the new state is on the
//     disk: a power loss after it keeps the new state.
func TestPowerLossLeavesTheOldOrTheNewArchive(t *testing.T) {
	for _, tc := range writeCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			template := t.TempDir()
			name := tc.setup(t, template)
			before, err := archiveState(filepath.Join(template, name), tc.opens)
			if err != nil && !IsDamage(err) {
				t.Fatalf("the state before: %v", err)
			}
			dir := copyDir(t, template)
			cfs := newCrashFS(t, dir, name)
			if err := withFS(cfs, func() error { return tc.run(filepath.Join(dir, name)) }); err != nil {
				t.Fatal(err)
			}
			after, err := archiveState(filepath.Join(dir, name), tc.opens)
			if err != nil {
				t.Fatalf("the state after: %v", err)
			}

			absent, data := cfs.durable()
			if got, _, err := openState(t, name, absent, data, tc.opens, false); err != nil || got != after {
				t.Errorf("a power loss after the operation reported success: the archive is not the new one (%v):\n%s", err, got)
			}

			states := make([]crashState, 0, len(cfs.states))
			for _, s := range cfs.states {
				states = append(states, s)
			}
			sort.Slice(states, func(i, j int) bool { return states[i].op < states[j].op })
			repairs := 0
			for _, s := range states {
				what := fmt.Sprintf("power loss after %s, %s", s.after, s.how)
				got, repaired, err := openState(t, name, s.absent, s.data, tc.opens, !cfs.renamed)
				if repaired {
					repairs++
				}
				switch {
				case err != nil:
					t.Errorf("%s: %v", what, err)
				case got != before && got != after:
					t.Errorf("%s: the archive is neither the old nor the new one:\n%s", what, got)
				}
			}
			t.Logf("%d operations, %d states, %d of them repaired", cfs.ops, len(states), repairs)
		})
	}
}
