package archive

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
)

// DiffConfig drives --diff (doc/design.md 9.8).
type DiffConfig struct {
	Archive string
	// BaseDir is -C: the directory that holds the tree. "" is the working
	// directory.
	BaseDir      string
	Patterns     []string
	Exclude      []string
	Regex        fsutil.Regexps // -R
	ExcludeRegex fsutil.Regexps
	// Dereference and OneFileSystem walk the tree as create did with them.
	Dereference   bool
	OneFileSystem bool
	// StripComponents is --strip-components: the tree on disk is what
	// extraction with it writes (doc/design.md 10.14). The patterns match
	// the stored paths, before the strip.
	StripComponents int
	// Metadata leaves out what --no-owner, --no-xattrs and --no-acls name.
	Metadata MetadataOptions
	Open     OpenOptions
	// Workers is the number of files read at one time; 0 means GOMAXPROCS.
	Workers   int
	KeepGoing bool
	Reporter  Reporter
}

// The kinds of a Difference, in the order that a path reports them.
const (
	DiffMissing  = "missing"  // the member is not on disk
	DiffExtra    = "extra"    // the disk has a path that the archive does not
	DiffType     = "type"     // one is a file, the other a directory, ...
	DiffSize     = "size"     // a file of another size
	DiffContent  = "content"  // a file of the same size with other bytes
	DiffLink     = "link"     // a symbolic link with another target
	DiffHardlink = "hardlink" // not the same file as its hardlink target
	DiffDevice   = "device"   // other device numbers
	DiffMode     = "mode"
	DiffOwner    = "owner"
	DiffMTime    = "mtime"
	DiffXattrs   = "xattrs"
	DiffACLs     = "acls"
)

var diffRank = map[string]int{
	DiffMissing: 0, DiffExtra: 1, DiffType: 2, DiffSize: 3, DiffContent: 4,
	DiffLink: 5, DiffHardlink: 6, DiffDevice: 7, DiffMode: 8, DiffOwner: 9,
	DiffMTime: 10, DiffXattrs: 11, DiffACLs: 12,
}

// Difference is one way in which a path on disk is not what the archive
// holds. Archive and Disk give the two values, where they have a short form.
// Names lists the extended attributes that differ.
type Difference struct {
	Path    string
	Kind    string
	Archive string
	Disk    string
	Names   []string
}

// DiffResult says what --diff found.
type DiffResult struct {
	// Differences are in the order of their paths.
	Differences []Difference
	// Compared counts the members that are on disk too.
	Compared int
	// Paths counts the paths with at least one difference.
	Paths  int
	Failed int
	// Collided counts the members left out because a later member has the
	// same path after --strip-components.
	Collided int
}

// DiffArchive compares the live members of an archive with the tree on disk
// (doc/design.md 9.8). It reports the members that are not on disk, the
// paths on disk that are not in the archive, and the members whose type,
// content or metadata are different. It changes nothing.
//
// The content check reads each file and compares its digest with the
// member's digest. It reads no member data from the archive, so it does not
// check the archive itself: --verify does that.
func DiffArchive(cfg DiffConfig) (DiffResult, error) {
	var res DiffResult

	r, err := OpenWith(cfg.Archive, cfg.Open)
	if err != nil {
		return res, err
	}
	defer r.Close()

	live := excludeMembers(r.Members(), cfg.Exclude, cfg.ExcludeRegex)
	// dirs holds the directories of the archive, before the patterns select:
	// they decide where the archived tree starts on disk.
	dirs := map[string]bool{}
	for i := range live {
		if err := checkPath(&live[i]); err != nil {
			return res, err
		}
		if live[i].Type == format.TypeDir {
			if p, ok := stripPath(live[i].Path, cfg.StripComponents); ok {
				dirs[p] = true
			}
		}
	}
	selected, err := selectMembers(live, cfg.Patterns, cfg.Regex)
	if err != nil {
		return res, err
	}
	byID := map[uint64]*format.Member{}
	for i := range r.index.Members {
		byID[r.index.Members[i].ID] = &r.index.Members[i]
	}
	// prefixes holds what the strip removes from the selected members. A
	// path on disk is in the comparison when one of them before it gives a
	// path that the patterns select (differ.inScope).
	prefixes := map[string]bool{}
	if cfg.StripComponents > 0 {
		for i := range selected {
			if rest, ok := stripPath(selected[i].Path, cfg.StripComponents); ok {
				prefixes[selected[i].Path[:len(selected[i].Path)-len(rest)-1]] = true
			}
		}
		sort.SliceStable(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
		selected, res.Collided = stripMembers(selected, cfg.StripComponents, cfg.Reporter, "not compared")
		// A hardlink is checked against its target's path on disk, which
		// is the target's path after the strip. A target that the strip
		// leaves out has no path, and is not checked.
		for id, m := range byID {
			c := *m
			c.Path, _ = stripPath(m.Path, cfg.StripComponents)
			byID[id] = &c
		}
	}

	// The writer never stores the root of the tree, ".". Another writer can:
	// it is not compared, as extraction does not apply it (withoutRoot).
	want := map[string]*format.Member{}
	roots := map[string]bool{}
	var total int64
	for i := range selected {
		m := &selected[i]
		if m.Path == fsutil.RootPath {
			continue
		}
		want[m.Path] = m
		roots[treeRoot(m.Path, dirs)] = true
		if c := contentOf(m, byID); c.Type.HasPayload() {
			total += int64(c.Size)
		}
	}

	// A member added by its own path, as -r a/b/c adds it, can have no
	// member for its directory a/b. Extraction makes that directory, so on
	// disk it is not a path that the archive lacks.
	parents := map[string]bool{}
	for p := range want {
		for dir := path.Dir(p); dir != "." && !parents[dir]; dir = path.Dir(dir) {
			parents[dir] = true
		}
	}
	d := &differ{cfg: cfg, r: r, byID: byID, want: want, parents: parents, seen: map[string]bool{},
		extraDirs: map[string]bool{}, prefixes: sortedKeys(prefixes)}
	d.progress = progressOf(cfg.Reporter)
	if d.progress != nil {
		d.progress.Total(total)
	}
	if fi, err := os.Stat(cfg.Archive); err == nil {
		d.archive = fi
	}
	base := cfg.BaseDir
	if base == "" {
		base = "."
	}
	if d.root, err = os.OpenRoot(base); err != nil {
		return res, fmt.Errorf("opening %s: %w", base, err)
	}
	defer d.root.Close()

	d.startWorkers()
	walkErr := d.walk(sortedKeys(roots))
	d.stopWorkers()
	if walkErr == nil {
		walkErr = d.firstErr
	}
	if walkErr != nil {
		return res, walkErr
	}
	d.checkHardlinks()

	// A member that the walk did not find is not on disk. Under a directory
	// that is not on disk, only the directory is reported.
	missingDirs := map[string]bool{}
	var missing []*format.Member
	for p, m := range want {
		if !d.seen[p] {
			missing = append(missing, m)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })
	for _, m := range missing {
		if m.Type == format.TypeDir {
			missingDirs[m.Path] = true
		}
		if !under(m.Path, missingDirs) {
			d.diffs = append(d.diffs, Difference{Path: m.Path, Kind: DiffMissing})
		}
	}

	sort.SliceStable(d.diffs, func(i, j int) bool {
		a, b := d.diffs[i], d.diffs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return diffRank[a.Kind] < diffRank[b.Kind]
	})
	res.Differences = d.diffs
	res.Compared = d.compared
	res.Failed = d.failed
	for i := range res.Differences {
		if i == 0 || res.Differences[i].Path != res.Differences[i-1].Path {
			res.Paths++
		}
	}
	return res, nil
}

// treeRoot returns the path where the walk on disk starts for the member at
// p: its highest ancestor that is a directory of the archive, or p itself. A
// file archived alone is walked alone, so that its neighbours on disk are not
// reported as paths that the archive does not have.
func treeRoot(p string, dirs map[string]bool) string {
	root := p
	for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
		if dirs[dir] {
			root = dir
		}
	}
	return root
}

// under reports whether a proper ancestor of p is in dirs.
func under(p string, dirs map[string]bool) bool {
	for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
		if dirs[dir] {
			return true
		}
	}
	return false
}

// contentOf returns the member that holds m's content: the target of a
// hardlink, or m itself. The target can be a tombstone that -u replaced.
func contentOf(m *format.Member, byID map[uint64]*format.Member) *format.Member {
	if m.Type == format.TypeHardlink {
		if t, ok := byID[m.HardlinkTo]; ok {
			return t
		}
	}
	return m
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// differ holds the state of one --diff.
type differ struct {
	cfg  DiffConfig
	r    *Reader
	root *os.Root
	byID map[uint64]*format.Member
	// parents holds the directories above the members of want.
	parents map[string]bool
	// prefixes are the leading components that --strip-components removed,
	// in order. They are empty without it.
	prefixes []string
	want     map[string]*format.Member // the selected members, by path
	archive  os.FileInfo               // the archive file, which the walk skips
	progress Progress

	// The walk's own state, on the walking goroutine only.
	seen      map[string]bool // the members found on disk
	extraDirs map[string]bool // the directories reported as not in the archive
	links     []linkCheck
	compared  int

	jobs chan contentJob
	wg   sync.WaitGroup

	// mu guards what the workers share with the walk.
	mu       sync.Mutex
	diffs    []Difference
	failed   int
	firstErr error
}

// contentJob is one file to read and compare with its member's digest. The
// walk opens the file, through the directory that it walked, and the worker
// reads it and closes it.
type contentJob struct {
	content *format.Member
	e       entry
	f       *os.File
}

// linkCheck is a hardlink member found on disk, whose target is checked after
// the walk.
type linkCheck struct {
	m    *format.Member
	info os.FileInfo
}

func (d *differ) add(diffs ...Difference) {
	d.mu.Lock()
	d.diffs = append(d.diffs, diffs...)
	d.mu.Unlock()
}

// fail records an error of one path. Under --keep-going it is reported and
// the run goes on; otherwise the first error stops the run.
func (d *differ) fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failed++
	if d.cfg.KeepGoing {
		if d.cfg.Reporter != nil {
			d.cfg.Reporter.Warn("%v", err)
		}
		return
	}
	if d.firstErr == nil {
		d.firstErr = err
	}
}

func (d *differ) stopped() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.firstErr
}

func (d *differ) startWorkers() {
	workers := d.cfg.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	d.jobs = make(chan contentJob, workers)
	newHash := func() hash.Hash { return newDigest(d.r.keys) }
	for range workers {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for job := range d.jobs {
				if d.stopped() != nil {
					job.f.Close()
					continue // drain
				}
				same, err := sameContentOf(job.content, job.f, job.e, newHash)
				job.f.Close()
				if d.progress != nil {
					d.progress.Advance(int64(job.content.Size))
				}
				switch {
				case err != nil:
					d.fail(err)
				case !same:
					d.add(Difference{Path: job.e.Stored, Kind: DiffContent})
				}
			}
		}()
	}
}

func (d *differ) stopWorkers() {
	close(d.jobs)
	d.wg.Wait()
}

// walk visits each root of the archived tree on disk. A root that is not on
// disk is not walked: its members are then reported as missing.
func (d *differ) walk(roots []string) error {
	opt := walkOptions{
		root:          d.root,
		baseDir:       d.cfg.BaseDir,
		dereference:   d.cfg.Dereference,
		exclude:       d.cfg.Exclude,
		regex:         d.cfg.Regex,
		excludeRegex:  d.cfg.ExcludeRegex,
		oneFileSystem: d.cfg.OneFileSystem,
		onError: func(src string, err error) error {
			d.fail(err)
			return d.stopped()
		},
	}
	// The selection options match stored paths. After --strip-components,
	// the paths on disk are shorter, and inScope tests them instead.
	if d.cfg.StripComponents > 0 {
		opt.exclude, opt.regex, opt.excludeRegex = nil, nil, nil
	}
	wk := newWalker(opt, d.visit)
	for _, root := range roots {
		there, err := d.rootThere(root)
		if err != nil {
			return err
		}
		if !there {
			continue
		}
		if err := wk.Walk(root); err != nil {
			return err
		}
		if err := d.stopped(); err != nil {
			return err
		}
	}
	return nil
}

// rootThere reports whether a root of the tree is on disk. The root's path
// comes from the archive, which can be hostile: os.Root refuses a path that
// leaves the base directory through a symbolic link, as extraction does
// (doc/design.md 7.5).
func (d *differ) rootThere(root string) (bool, error) {
	_, err := d.root.Lstat(root)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return false, nil
	}
	// os.Root reports an escape with an unexported error, so the parents
	// of the root are checked for a link, as unsafeOrRaw does.
	for dir := path.Dir(root); dir != "."; dir = path.Dir(dir) {
		if fi, lerr := d.root.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%w: member %q is under the symbolic link %q, which leads out of %s",
				fsutil.ErrUnsafePath, root, dir, d.root.Name())
		}
	}
	return false, fmt.Errorf("%s: %w", root, err)
}

// inScope reports whether the path p on disk, which is not a member, is one
// that the selection options take: a path that the archive lacks, or one to
// leave out. After --strip-components, p is in scope when a removed prefix
// before it gives a stored path that the options select.
func (d *differ) inScope(p string) bool {
	if d.cfg.StripComponents == 0 {
		// The walk applied the other options.
		return len(d.cfg.Patterns) == 0 || fsutil.MatchAny(d.cfg.Patterns, p)
	}
	for _, prefix := range d.prefixes {
		stored := prefix + "/" + p
		if (len(d.cfg.Patterns) == 0 || fsutil.MatchAny(d.cfg.Patterns, stored)) &&
			(len(d.cfg.Regex) == 0 || d.cfg.Regex.MatchAny(stored)) &&
			!fsutil.MatchAnyOrParent(d.cfg.Exclude, stored) &&
			!d.cfg.ExcludeRegex.MatchAnyOrParent(stored) {
			return true
		}
	}
	return false
}

// visit compares one path of the walk with its member.
func (d *differ) visit(e entry) error {
	if err := d.stopped(); err != nil {
		return err
	}
	// The archive is never in itself (doc/design.md 7.2).
	if d.archive != nil && os.SameFile(e.Info, d.archive) {
		return nil
	}
	m, ok := d.want[e.Stored]
	if !ok && (!d.inScope(e.Stored) || e.Kind == kindDir && d.parents[e.Stored]) {
		return nil
	}
	if !ok {
		// Create skips a socket, so it is not a path that the archive lacks.
		// Under a directory that is not in the archive, only the directory
		// is reported.
		if e.Kind == kindSocket || under(e.Stored, d.extraDirs) {
			return nil
		}
		if e.Kind == kindDir {
			d.extraDirs[e.Stored] = true
		}
		d.add(Difference{Path: e.Stored, Kind: DiffExtra})
		return nil
	}
	d.seen[e.Stored] = true
	d.compared++
	if d.cfg.Reporter != nil {
		d.cfg.Reporter.Member(m)
	}

	// A file is opened here, while the walk holds its directory, and not by
	// its path in a worker later (doc/Security_Audit.md, finding 11). Its
	// attributes and its content come from what this opens.
	var f *os.File
	var openErr error
	if e.Kind == kindFile && (m.Type == format.TypeReg || m.Type == format.TypeHardlink) {
		f, openErr = openWalked(e)
	}
	open := f
	if e.Kind == kindDir {
		open = e.self
	}
	diffs, content, err := compareEntry(m, contentOf(m, d.byID), e, d.cfg.Metadata, open, openErr)
	d.add(diffs...)
	if err == nil && content != nil && f == nil {
		err = openErr
	}
	if err != nil {
		if f != nil {
			f.Close()
		}
		d.fail(err)
		return d.stopped()
	}
	sameType := len(diffs) == 0 || diffs[0].Kind != DiffType
	if m.Type == format.TypeHardlink && sameType {
		d.links = append(d.links, linkCheck{m: m, info: e.Info})
	}
	if content != nil {
		d.jobs <- contentJob{content: content, e: e, f: f}
		return nil
	}
	if f != nil {
		f.Close()
	}
	if c := contentOf(m, d.byID); d.progress != nil && c.Type.HasPayload() {
		d.progress.Advance(int64(c.Size))
	}
	return nil
}

// checkHardlinks checks that each hardlink on disk is the same file as its
// target. A target that is not live, or not on disk, is not checked: a
// missing target is reported as missing. Nor is a target whose path another
// member holds after --strip-components.
func (d *differ) checkHardlinks() {
	for _, l := range d.links {
		t, ok := d.byID[l.m.HardlinkTo]
		if !ok || t.Dead || t.Path == "" {
			continue
		}
		// After --strip-components, another member can hold the target's
		// path. Extraction then gave the link a copy of the content, and
		// the file at that path is not the target.
		if w, held := d.want[t.Path]; held && w.ID != t.ID {
			continue
		}
		fi, err := d.root.Lstat(t.Path)
		if err != nil {
			continue
		}
		if !os.SameFile(fi, l.info) {
			d.add(Difference{Path: l.m.Path, Kind: DiffHardlink, Archive: t.Path})
		}
	}
}

// compareEntry compares the metadata of member m with the path e on disk.
// content holds m's content: the target of a hardlink, or m. When the content
// can be the same, compareEntry returns the member to compare it with, and
// the caller reads the file. f is e open, for its attributes: a file that the
// caller opened, or the directory that the walk opened. For a file that did
// not open, f is nil and openErr says why.
func compareEntry(m, content *format.Member, e entry, opt MetadataOptions, f *os.File, openErr error) ([]Difference, *format.Member, error) {
	var diffs []Difference
	add := func(kind, archive, disk string) {
		diffs = append(diffs, Difference{Path: m.Path, Kind: kind, Archive: archive, Disk: disk})
	}

	wantType := m.Type
	if wantType == format.TypeHardlink {
		wantType = format.TypeReg
	}
	gotType := memberTypeFor(e.Kind)
	if e.Kind == kindSocket {
		gotType = format.TypeSocket
	}
	if gotType != wantType {
		add(DiffType, typeName(wantType), typeName(gotType))
		return diffs, nil, nil
	}

	var check *format.Member
	switch m.Type {
	case format.TypeSymlink:
		if m.LinkTarget != e.LinkTarget {
			add(DiffLink, m.LinkTarget, e.LinkTarget)
		}
	case format.TypeCharDev, format.TypeBlockDev:
		if len(m.RDev) == 2 && (m.RDev[0] != e.Sys.Major || m.RDev[1] != e.Sys.Minor) {
			add(DiffDevice, fmt.Sprintf("%d,%d", m.RDev[0], m.RDev[1]),
				fmt.Sprintf("%d,%d", e.Sys.Major, e.Sys.Minor))
		}
	case format.TypeReg, format.TypeHardlink:
		if size := uint64(e.Info.Size()); size != content.Size {
			add(DiffSize, strconv.FormatUint(content.Size, 10), strconv.FormatUint(size, 10))
		} else if content.Type.HasPayload() {
			check = content
		}
	}

	// A symbolic link's own mode means nothing (doc/design.md 7.6).
	if mode := meta.UnixMode(e.Info.Mode()); m.Type != format.TypeSymlink && mode != m.Mode {
		add(DiffMode, fmt.Sprintf("%04o", m.Mode), fmt.Sprintf("%04o", mode))
	}
	// An archive made with --no-owner records no owner, so there is nothing
	// to compare.
	if !opt.NoOwner && m.UID != nil && m.GID != nil && e.Sys.OK &&
		(*m.UID != e.Sys.UID || *m.GID != e.Sys.GID) {
		add(DiffOwner, fmt.Sprintf("%d:%d", *m.UID, *m.GID), fmt.Sprintf("%d:%d", e.Sys.UID, e.Sys.GID))
	}
	if mtime := e.Info.ModTime().UnixNano(); mtime != m.MTimeNanos {
		add(DiffMTime, formatNanos(m.MTimeNanos), formatNanos(mtime))
	}

	// Create records extended attributes on directories and files only.
	if m.Type == format.TypeDir || m.Type == format.TypeReg {
		// The differences found so far are still differences. macOS, for
		// one, cannot list the attributes of a file that it cannot read, and
		// its mode is then the difference that tells why.
		if f == nil && openErr != nil && !(opt.NoXattrs && opt.NoACLs) {
			return diffs, nil, openErr
		}
		got, err := readXattrs(e, f, opt, nil)
		if err != nil {
			return diffs, nil, err
		}
		var xattrs, acls []string
		for _, name := range xattrNames(m.Xattrs, got) {
			if !opt.records(name) {
				continue
			}
			a, inArchive := m.Xattrs[name]
			b, onDisk := got[name]
			if inArchive && onDisk && bytes.Equal(a, b) {
				continue
			}
			if meta.ClassifyXattr(name) == meta.XattrACL {
				acls = append(acls, name)
			} else {
				xattrs = append(xattrs, name)
			}
		}
		if len(xattrs) > 0 {
			diffs = append(diffs, Difference{Path: m.Path, Kind: DiffXattrs, Names: xattrs})
		}
		if len(acls) > 0 {
			diffs = append(diffs, Difference{Path: m.Path, Kind: DiffACLs, Names: acls})
		}
	}
	return diffs, check, nil
}

// xattrNames returns the names in a or b, in order.
func xattrNames(a, b map[string][]byte) []string {
	set := map[string]bool{}
	for name := range a {
		set[name] = true
	}
	for name := range b {
		set[name] = true
	}
	return sortedKeys(set)
}

// typeName is the word for a member type in a difference.
func typeName(t format.MemberType) string {
	switch t {
	case format.TypeReg:
		return "file"
	case format.TypeDir:
		return "directory"
	case format.TypeSymlink:
		return "symbolic link"
	case format.TypeFIFO:
		return "FIFO"
	case format.TypeSocket:
		return "socket"
	case format.TypeCharDev:
		return "character device"
	case format.TypeBlockDev:
		return "block device"
	case "":
		return "unsupported file"
	}
	return string(t)
}

// formatNanos shows a time to the nanosecond, in UTC, so that two times that
// differ by less than a second do not look the same.
func formatNanos(ns int64) string {
	return time.Unix(0, ns).UTC().Format("2006-01-02 15:04:05.000000000")
}
