package archive

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/pipeline"
)

// Reporter receives progress and warnings. A nil Reporter is silent.
type Reporter interface {
	// Member is called as each member is processed, for -v.
	Member(m *format.Member)
	// Warn reports a recoverable problem, such as a skipped member under
	// --keep-going, or the one-shot notice that leading slashes were removed.
	Warn(format string, args ...any)
}

// Stats summarise a completed operation.
type Stats struct {
	Members int    // members actually written
	Bytes   uint64 // plaintext bytes of those members
	Failed  int
	Skipped int // left alone by the overwrite or conflict policy

	Unchanged int // found up to date by -u
	Replaced  int // live members that this run tombstoned
}

// CreateConfig drives archive creation.
type CreateConfig struct {
	Archive string
	Paths   []string
	Options Options
	BaseDir string // resolve Paths relative to this directory; "" means the current one
	// Dereference is -h: archive what a symlink points at, not the link.
	Dereference bool
	KeepGoing   bool
	Reporter    Reporter

	// Exclude lists patterns for --exclude and -X. An excluded directory is
	// not entered.
	Exclude []string
	// Regex is -R: only the walked paths that match are stored, and each
	// expression must match one (doc/design.md 10.11). ExcludeRegex is
	// --exclude-regex, which works like Exclude.
	Regex        fsutil.Regexps
	ExcludeRegex fsutil.Regexps
	// OneFileSystem is --one-file-system: a mount point is recorded, empty.
	OneFileSystem bool
	// Metadata selects which metadata is recorded.
	Metadata MetadataOptions

	// Encryption, when set, seals every member and authenticates the index.
	Encryption *EncryptionConfig
	// Workers is the number of compressing goroutines; 0 means GOMAXPROCS.
	Workers int
	// MemoryLimit bounds the bytes in flight; 0 picks a default from the
	// machine and the worker count.
	MemoryLimit int64
	// SpillThreshold is where a member's payload moves from memory to a
	// temporary file; 0 means DefaultSpillThreshold.
	SpillThreshold int64
}

// CreateArchive walks the given paths and writes them into a new archive.
//
// Regular files, directories and symbolic links are stored. Anything else -
// devices, sockets, named pipes - is refused rather than skipped silently: an
// archive that quietly omits what was asked for is worse than one that
// refuses to be written. --keep-going downgrades that to a warning.
func CreateArchive(cfg CreateConfig) (Stats, error) {
	var stats Stats

	workers := cfg.Workers
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}

	// The encoder is shared by every worker, so it has to be built knowing
	// how many there are.
	opts := cfg.Options
	opts.Concurrency = workers

	if cfg.Encryption != nil {
		if err := cfg.Encryption.apply(&opts); err != nil {
			return stats, err
		}
		defer opts.Keys.Zero()
	}

	w, err := Create(cfg.Archive, opts)
	if err != nil {
		return stats, err
	}
	if err := w.useDictionary(func(size int) ([][]byte, error) { return sampleTree(w, cfg, size) }, warnOf(cfg.Reporter)); err != nil {
		w.Abort()
		return stats, err
	}

	stats, _, err = addPaths(w, cfg, workers, nil)
	if err != nil {
		// A failed create leaves no archive behind: a file with no trailer is
		// not readable, and leaving one invites someone to try.
		w.Abort()
		return stats, err
	}
	// A Close that fails removes the temporary file, by the same rule.
	return stats, w.Close()
}

// addPaths walks cfg.Paths into w through the compression pipeline, and
// returns when the pipeline has drained. It neither closes nor aborts w: that
// is the caller's decision. prepare, when not nil, configures the capturer
// before the walk starts; append and update use it to install the conflict
// rules.
func addPaths(w *Writer, cfg CreateConfig, workers int, prepare func(*capturer)) (Stats, *capturer, error) {
	var stats Stats

	warnedStrip := false
	rep := cfg.Reporter

	// The file being written exists before the walk, so a walk that reaches
	// it would archive the file into itself - reading bytes it is still
	// writing, and growing without bound. tar has the same guard. The
	// comparison is by inode, so it holds through a symlink or a different
	// spelling of the same path. For a create, the old archive at the path is
	// a different inode, and it is skipped as well.
	oldArchive, oldErr := os.Stat(cfg.Archive)
	warnedSelf := false

	spill := cfg.SpillThreshold
	if spill <= 0 {
		spill = DefaultSpillThreshold
	}

	// emitted is touched only by the pipeline's emitting goroutine, and read
	// only after Finish has waited for it.
	var emitted Stats

	builder := pipeline.New(pipeline.Config{
		Workers:        workers,
		ChunkSize:      w.chunkSize,
		Budget:         pipeline.NewBudget(budgetFor(cfg.MemoryLimit, workers, w.chunkSize)),
		SpillThreshold: spill,
		SpillDir:       filepath.Dir(cfg.Archive),
		Encoder:        w.Encoder(),
		Stored:         w.CodecRef() == format.NoCodec,
		NewSealer:      w.newSealer,
		Emit: func(m *format.Member, payload io.WriterTo) error {
			if err := w.AppendMember(m, payload); err != nil {
				return err
			}
			emitted.Members++
			if m.Type.HasPayload() {
				emitted.Bytes += m.Size
			}
			if rep != nil {
				rep.Member(m)
			}
			return nil
		},
	})
	builder.Start()
	capture := newCapturer(w, builder, cfg.Metadata)
	capture.progress = progressOf(rep)
	capture.warn = func(f string, args ...any) {
		if rep != nil {
			rep.Warn(f, args...)
		}
	}
	if prepare != nil {
		prepare(capture)
	}

	visit := func(e entry) error {
		// Both the file being written and the one it replaces: a create
		// writes to a temporary file, and the old archive at the path would
		// otherwise go into the new one.
		if w.SameFile(e.Info) || (oldErr == nil && os.SameFile(e.Info, oldArchive)) {
			if !warnedSelf {
				warnedSelf = true
				if rep != nil {
					rep.Warn("%s is the archive being written; not archiving it", e.Src)
				}
			}
			return nil
		}
		if e.Stripped && !warnedStrip {
			warnedStrip = true
			if rep != nil {
				rep.Warn("removing leading '/' or '..' from member names")
			}
		}

		addErr := capture.submit(e)
		if errors.Is(addErr, errUnchanged) {
			stats.Unchanged++
			return nil
		}
		var skipped *errSkipped
		if errors.As(addErr, &skipped) {
			stats.Skipped++
			if rep != nil {
				rep.Warn("%v", skipped)
			}
			return nil
		}
		// A conflict under --on-conflict=error stops the run whatever
		// --keep-going says: the user asked for the archive to stay as it was.
		if addErr != nil && !errors.Is(addErr, ErrConflict) {
			stats.Failed++
			if cfg.KeepGoing {
				if rep != nil {
					rep.Warn("%v", addErr)
				}
				return nil
			}
		}
		return addErr
	}

	wk := newWalker(walkOptions{
		baseDir:       cfg.BaseDir,
		dereference:   cfg.Dereference,
		exclude:       cfg.Exclude,
		regex:         cfg.Regex,
		excludeRegex:  cfg.ExcludeRegex,
		oneFileSystem: cfg.OneFileSystem,
	}, visit)
	var walkErr error
	for _, p := range cfg.Paths {
		if walkErr = wk.Walk(p); walkErr != nil {
			break
		}
	}
	if walkErr == nil {
		walkErr = wk.unmatched()
	}

	// Finish drains the pool whatever happened, so that no goroutine is left
	// running and no spill file is left open.
	finishErr := builder.Finish()
	if walkErr == nil {
		walkErr = finishErr
	}

	stats.Members = emitted.Members
	stats.Bytes = emitted.Bytes
	return stats, capture, walkErr
}

// EncryptionConfig is what a caller supplies to encrypt a new archive.
type EncryptionConfig struct {
	// Passphrase is consumed once, to derive the keys. The caller keeps
	// ownership and should zero it afterwards.
	Passphrase []byte
	Params     crypt.KDFParams
	// EncryptIndex hides the metadata as well. Authentication of the index
	// does not depend on it (doc/design.md 6.4).
	EncryptIndex bool
}

// apply runs the key schedule for a new archive and fills in the writer's
// options.
//
// The archive id is generated here rather than in the writer, because the key
// schedule is bound to it: deriving first and choosing the id afterwards would
// mean keys that do not match the archive they protect.
func (e *EncryptionConfig) apply(opts *Options) error {
	if len(e.Passphrase) == 0 {
		return errors.New("an empty passphrase cannot protect anything")
	}

	params := e.Params
	if params == (crypt.KDFParams{}) {
		params = crypt.DefaultKDFParams
	}
	if err := params.Validate(); err != nil {
		return err
	}
	if err := checkAffordable(params); err != nil {
		return err
	}

	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return fmt.Errorf("generating an archive id: %w", err)
	}
	// A random data key, wrapped for the passphrase: the passphrase makes
	// none of the keys, so it can change later (doc/design.md 6.2, 9.7).
	dataKey, err := crypt.NewDataKey()
	if err != nil {
		return err
	}
	keys, err := crypt.NewKeys(dataKey, uuid)
	clear(dataKey)
	if err != nil {
		return err
	}
	salt, wrapped, err := keys.Wrap(e.Passphrase, params)
	if err != nil {
		keys.Zero()
		return err
	}

	opts.Keys = keys
	opts.Salt = salt
	opts.WrappedKey = wrapped
	opts.KDFParams = params
	opts.EncryptIndex = e.EncryptIndex
	opts.ArchiveUUID = uuid
	return nil
}

// checkAffordable refuses key derivation that this machine cannot survive.
//
// Argon2id allocates its memory parameter outright, so asking for more than
// the machine has is not slow - it is an out-of-memory kill with no
// explanation. Saying so first is the difference between a diagnostic and a
// dead process (doc/design.md A.3).
func checkAffordable(p crypt.KDFParams) error {
	return checkAffordableOn(p, totalMemory())
}

// checkAffordableOn is checkAffordable for a given amount of RAM, so the
// decision can be tested without owning a small machine.
func checkAffordableOn(p crypt.KDFParams, ram int64) error {
	if ram <= 0 {
		return nil
	}
	if need := p.MemoryBytes(); need > ram/2 {
		return fmt.Errorf("deriving the key needs %d MiB, more than half this machine's %d MiB; "+
			"lower --kdf-memory, or run this where the archive was made",
			need/(1<<20), ram/(1<<20))
	}
	return nil
}

// budgetFor sizes the in-flight memory allowance.
//
// The design asks for the smaller of a quarter of RAM and a few chunks per
// worker (doc/design.md 8.1). The second term is what actually binds on a large
// machine, and the first is what keeps a small one usable.
func budgetFor(limit int64, workers, chunkSize int) int64 {
	if limit > 0 {
		return limit
	}
	byWorkers := int64(workers) * 4 * int64(chunkSize)
	if ram := totalMemory(); ram > 0 {
		if quarter := ram / 4; quarter < byWorkers {
			return quarter
		}
	}
	return byWorkers
}

// ListConfig drives listing.
type ListConfig struct {
	Archive      string
	Patterns     []string
	Exclude      []string       // --exclude and -X
	Regex        fsutil.Regexps // -R
	ExcludeRegex fsutil.Regexps // --exclude-regex
	Passphrase   PassphraseFunc
	// RequireEncryption refuses an archive that is not encrypted; see
	// ErrNotEncrypted.
	RequireEncryption bool
}

// Listing is the result of a listing: the matching members, and what is
// needed to describe them - the codec catalog, and every live member by id so
// that a hardlink can name its target even when a pattern filtered it out.
type Listing struct {
	Members []format.Member
	Codecs  []format.CodecSpec
	byID    map[uint64]format.Member

	// Generation and Tombstoned describe the whole archive, whatever the
	// patterns selected.
	Generation uint64
	Tombstoned int
}

// Codec returns the catalog entry a member was stored with, and "none" for a
// member stored without a codec. A nil Listing - the verbose output of an
// extraction, which has no catalog to hand - reports false.
func (l *Listing) Codec(m *format.Member) (format.CodecSpec, bool) {
	if l == nil {
		return format.CodecSpec{}, false
	}
	if m.Codec < 0 || m.Codec >= len(l.Codecs) {
		return format.CodecSpec{Name: "none"}, true
	}
	return l.Codecs[m.Codec], true
}

// HardlinkTarget returns the path a hardlink member points at, or its id
// when there is no listing to look it up in.
func (l *Listing) HardlinkTarget(m *format.Member) string {
	if l == nil {
		return fmt.Sprintf("member %d", m.HardlinkTo)
	}
	return l.byID[m.HardlinkTo].Path
}

// ListArchive reads the index and returns the members matching the patterns,
// or all of them. Listing reads the index alone.
func ListArchive(cfg ListConfig) (*Listing, error) {
	r, err := OpenWith(cfg.Archive, OpenOptions{
		Passphrase: cfg.Passphrase, RequireEncryption: cfg.RequireEncryption,
	})
	if err != nil {
		return nil, err
	}
	defer r.Close()

	all := r.Members()
	l := &Listing{
		Codecs:     r.index.Codecs,
		byID:       map[uint64]format.Member{},
		Generation: r.tr.Generation,
	}
	for _, m := range r.AllMembers() { // tombstones too: a hardlink can point to one
		l.byID[m.ID] = m
		if m.Dead {
			l.Tombstoned++
		}
	}

	members, err := selectMembers(all, cfg.Patterns, cfg.Regex)
	if err != nil {
		return nil, err
	}
	members = excludeMembers(members, cfg.Exclude, cfg.ExcludeRegex)
	sort.Slice(members, func(i, j int) bool { return members[i].Path < members[j].Path })
	l.Members = members
	return l, nil
}

// List returns the members matching the patterns, or all of them.
func List(cfg ListConfig) ([]format.Member, error) {
	l, err := ListArchive(cfg)
	if err != nil {
		return nil, err
	}
	return l.Members, nil
}

// excludeMembers drops the members that match an exclude pattern, and
// everything under a directory that matches one.
func excludeMembers(members []format.Member, exclude []string, excludeRegex fsutil.Regexps) []format.Member {
	if len(exclude) == 0 && len(excludeRegex) == 0 {
		return members
	}
	out := members[:0:0]
	for _, m := range members {
		if !fsutil.MatchAny(exclude, m.Path) && !excludeRegex.MatchAnyOrParent(m.Path) {
			out = append(out, m)
		}
	}
	return out
}

// selectMembers keeps the members that match any pattern, and then, with -R,
// those that match any expression. No patterns means every member.
//
// Each pattern and each expression must match at least one member, or the
// result is ErrNoMatch:
// a mistyped name must be reported, not answered with an empty listing or an
// extraction that quietly leaves the file out. tar does the same. It lives
// here rather than in fsutil so that the path helpers stay free of the format
// types.
func selectMembers(members []format.Member, patterns []string, regex fsutil.Regexps) ([]format.Member, error) {
	members, err := selectByPattern(members, patterns)
	if err != nil || len(regex) == 0 {
		return members, err
	}
	matched := make([]bool, len(regex))
	out := make([]format.Member, 0, len(members))
	for _, m := range members {
		hit := false
		for i, re := range regex {
			if re.Match(m.Path) {
				matched[i], hit = true, true
			}
		}
		if hit {
			out = append(out, m)
		}
	}
	for i, ok := range matched {
		if !ok {
			return nil, fmt.Errorf("-R %q %w", regex[i].Expr, ErrNoMatch)
		}
	}
	return out, nil
}

func selectByPattern(members []format.Member, patterns []string) ([]format.Member, error) {
	if len(patterns) == 0 {
		return members, nil
	}
	matched := make([]bool, len(patterns))
	out := make([]format.Member, 0, len(members))
	for _, m := range members {
		hit := false
		for i, p := range patterns {
			if fsutil.Match(p, m.Path) {
				matched[i], hit = true, true
			}
		}
		if hit {
			out = append(out, m)
		}
	}
	for i, ok := range matched {
		if !ok {
			return nil, fmt.Errorf("%q %w", patterns[i], ErrNoMatch)
		}
	}
	return out, nil
}

func describeMode(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "a symbolic link"
	case mode&os.ModeDevice != 0:
		return "a device node"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeSocket != 0:
		return "a socket"
	default:
		return "an unsupported file type"
	}
}
