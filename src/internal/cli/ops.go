package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
)

// reporter turns -v and warnings into output on the right stream.
type reporter struct {
	out     io.Writer
	errOut  io.Writer
	verbose int
	quiet   bool
	long    bool
}

func (r *reporter) Member(m *format.Member) {
	if r.verbose == 0 {
		return
	}
	if r.long {
		fmt.Fprintln(r.out, longLine(nil, m, false))
		return
	}
	fmt.Fprintln(r.out, m.Path)
}

func (r *reporter) Warn(format string, args ...any) {
	if r.quiet {
		return
	}
	fmt.Fprintf(r.errOut, "eictar: "+format+"\n", args...)
}

// passphraseFor builds the source for this run.
func passphraseFor(o *Options, confirm bool) passphraseSource {
	return passphraseSource{file: o.PassphraseFile, env: o.PassphraseEnv, confirm: confirm}
}

// askFor returns a function the archive layer calls only if the archive turns
// out to need a key, so a plaintext archive never prompts.
func askFor(o *Options, rep *reporter) archive.PassphraseFunc {
	src := passphraseFor(o, false)
	return func() ([]byte, error) {
		src.warnIfInsecureSource(rep.Warn)
		return src.get()
	}
}

// checkCompress reports a bad compression spec as the mistake in the command
// line that it is (exit 2), before the archive file is touched.
func checkCompress(o *Options, stderr io.Writer) error {
	return checkSpec(o, o.Compress, "--compress", stderr)
}

// checkSpec builds an encoder for spec to check it, and warns when its window
// is larger than a chunk: the chunks are independent, so no match reaches
// back past the start of its chunk (doc/design.md 10.2).
func checkSpec(o *Options, spec CompressSpec, option string, stderr io.Writer) error {
	enc, err := codec.NewEncoder(spec.Name, codec.Params(spec.Params), 1)
	if err != nil {
		return &UsageError{fmt.Errorf("%s %s: %w", option, spec, err)}
	}
	defer enc.Close()
	if long, ok := enc.Resolved()["long"].(int); ok && !o.Quiet && Size(1)<<long > o.ChunkSize {
		fmt.Fprintf(stderr, "eictar: %s: a window of %s is larger than the chunk size %s, "+
			"so it has no effect; raise --chunk-size to use it\n", option, Size(1)<<long, o.ChunkSize)
	}
	return nil
}

// addConfig builds what create, append and update share: which paths to
// walk, and how to compress them.
func addConfig(o *Options, rep *reporter) (archive.CreateConfig, error) {
	var cfg archive.CreateConfig
	base, err := createBaseDir(o)
	if err != nil {
		return cfg, err
	}
	paths, err := gatherPaths(o)
	if err != nil {
		return cfg, err
	}
	exclude, err := gatherExcludes(o)
	if err != nil {
		return cfg, err
	}
	return archive.CreateConfig{
		Archive: o.Archive,
		Paths:   paths,
		BaseDir: base,
		Options: archive.Options{
			Codec:     o.Compress.Name,
			Params:    codec.Params(o.Compress.Params),
			ChunkSize: int(o.ChunkSize),
		},
		Dereference:   o.Dereference,
		KeepGoing:     o.KeepGoing,
		Exclude:       exclude,
		Regex:         o.regex,
		ExcludeRegex:  o.excludeRegex,
		OneFileSystem: o.OneFileSystem,
		NoDedup:       o.NoDedup,
		Metadata: archive.MetadataOptions{
			NoOwner: o.NoOwner, NoXattrs: o.NoXattrs, NoACLs: o.NoACLs,
		},
		Workers:        o.Workers,
		MemoryLimit:    int64(o.MemoryLimit),
		SpillThreshold: int64(o.SpillThreshold),
		Reporter:       rep,
	}, nil
}

func runCreate(o *Options, stdout, stderr io.Writer) error {
	if err := checkCompress(o, stderr); err != nil {
		return err
	}
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	cfg, err := addConfig(o, rep)
	if err != nil {
		return err
	}

	if o.Encrypt {
		src := passphraseFor(o, true)
		src.warnIfInsecureSource(rep.Warn)

		passphrase, err := src.get()
		if err != nil {
			return err
		}
		defer zeroBytes(passphrase)

		cfg.Encryption = &archive.EncryptionConfig{
			Passphrase:   passphrase,
			Params:       crypt.KDFParams{Time: o.KDFTime, Memory: o.KDFMemory, Threads: o.KDFThreads},
			EncryptIndex: o.EncryptIdx,
		}
	}

	var done func()
	cfg.Reporter, done = withProgress(o, rep, stderr)
	stats, err := archive.CreateArchive(cfg)
	done()
	if err != nil {
		return err
	}
	if stats.Failed > 0 {
		return &partialError{failed: stats.Failed}
	}
	return nil
}

func runList(o *Options, stdout, stderr io.Writer) error {
	exclude, err := gatherExcludes(o)
	if err != nil {
		return err
	}
	l, err := archive.ListArchive(archive.ListConfig{
		Archive:           o.Archive,
		Patterns:          o.Args,
		Exclude:           exclude,
		Regex:             o.regex,
		ExcludeRegex:      o.excludeRegex,
		Passphrase:        askFor(o, &reporter{errOut: stderr, quiet: o.Quiet}),
		RequireEncryption: o.expectsEncryption(),
	})
	if err != nil {
		return err
	}

	// -v gives the long listing, as in tar, and -vv adds detail and a line
	// of totals (doc/design.md 10.9). --long is -v by another name.
	detail := o.Verbose >= 2
	switch {
	case o.JSON:
		return writeJSONList(stdout, l)
	case o.Long || o.Verbose > 0:
		rows := make([][]string, len(l.Members))
		for i := range l.Members {
			rows[i] = longColumns(l, &l.Members[i], detail)
		}
		// Sizes, stored sizes, percentages and chunk counts line up on the
		// right, as numbers do in ls and tar; everything else on the left.
		right := map[int]bool{2: true, 3: true, 4: true}
		if detail {
			right[6] = true
		}
		writeTable(stdout, rows, right)
		if detail {
			fmt.Fprintln(stdout, totalsLine(l))
		}
		return nil
	default:
		for i := range l.Members {
			fmt.Fprintln(stdout, l.Members[i].Path)
		}
	}
	return nil
}

func runExtract(o *Options, stdout, stderr io.Writer) error {
	exclude, err := gatherExcludes(o)
	if err != nil {
		return err
	}
	dest := o.Destination

	// -C names a directory to work in, and unlike -d it does not create one
	// (doc/design.md 7.1). Checking here keeps a typo from quietly producing
	// a new directory next to the one that was meant.
	if dest == "" && len(o.Chdir) > 0 {
		if len(o.Chdir) > 1 {
			return &UsageError{fmt.Errorf("more than one -C is not supported yet: it needs the interleaved semantics tar has")}
		}
		fi, err := os.Stat(o.Chdir[0])
		if err != nil {
			return fmt.Errorf("-C %s: %w", o.Chdir[0], err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("-C %s: not a directory", o.Chdir[0])
		}
		dest = o.Chdir[0]
	}

	var toStdout io.Writer
	if o.ToStdout {
		toStdout = stdout
	}

	policy := archive.OverwriteAlways
	switch o.Overwrite {
	case OverwriteNever:
		policy = archive.OverwriteNever
	case OverwriteNewer:
		policy = archive.OverwriteNewer
	}

	rep := &reporter{
		out:    stderrIfStdoutBusy(stdout, stderr, o.ToStdout),
		errOut: stderr, verbose: o.Verbose, quiet: o.Quiet, long: o.Long,
	}
	progress, done := withProgress(o, rep, stderr)
	defer done()

	stats, err := archive.Extract(archive.ExtractConfig{
		Archive:           o.Archive,
		Exclude:           exclude,
		Regex:             o.regex,
		ExcludeRegex:      o.excludeRegex,
		Passphrase:        askFor(o, rep),
		RequireEncryption: o.expectsEncryption(),
		Restore: archive.RestoreOptions{
			Permissions: o.PreservePermissions,
			Owner:       o.PreserveOwner,
			Devices:     o.PreserveDevices,
			NoXattrs:    o.NoXattrs,
			NoACLs:      o.NoACLs,
		},
		Destination: dest,
		Patterns:    o.Args,
		Overwrite:   policy,
		ToStdout:    toStdout,
		KeepGoing:   o.KeepGoing,
		Workers:     o.Workers,
		MemoryLimit: int64(o.MemoryLimit),
		Reporter:    progress,
	})
	if err != nil {
		return err
	}
	if stats.Failed > 0 {
		return &partialError{failed: stats.Failed}
	}
	return nil
}

// stderrIfStdoutBusy keeps -v output from corrupting -O content: when member
// data is going to stdout, the member names must not.
func stderrIfStdoutBusy(stdout, stderr io.Writer, toStdout bool) io.Writer {
	if toStdout {
		return stderr
	}
	return stdout
}

func runListCodecs(stdout io.Writer) error {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	for _, spec := range codec.Describe() {
		fmt.Fprintf(tw, "%s\t%s\n", spec.Name, spec.Description)
		for _, p := range spec.Params {
			rng := ""
			switch {
			case len(p.Choices) > 0:
				rng = "one of " + strings.Join(p.Choices, ", ")
			case p.Min != 0 || p.Max != 0:
				rng = fmt.Sprintf("%d..%d", p.Min, p.Max)
			}
			if p.Bare != "" {
				rng += fmt.Sprintf(", alone %s", p.Bare)
			}
			fmt.Fprintf(tw, "  %s\t%s (default %s%s)\n", p.Name, p.Description, p.Default,
				map[bool]string{true: "", false: ", " + strings.TrimPrefix(rng, ", ")}[rng == ""])
		}
	}
	return tw.Flush()
}

// createBaseDir resolves -C for create. Multiple -C options mean interleaved
// directory changes in tar, which needs argument order the flag parser does
// not preserve; until that is settled (doc/design.md 1.3, question 2), more
// than one is refused rather than silently misapplied.
func createBaseDir(o *Options) (string, error) {
	switch len(o.Chdir) {
	case 0:
		return "", nil
	case 1:
		fi, err := os.Stat(o.Chdir[0])
		if err != nil {
			return "", fmt.Errorf("-C %s: %w", o.Chdir[0], err)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("-C %s: not a directory", o.Chdir[0])
		}
		return o.Chdir[0], nil
	default:
		return "", &UsageError{fmt.Errorf("more than one -C is not supported yet: it needs the interleaved semantics tar has")}
	}
}

// gatherExcludes merges --exclude with the patterns of -X/--exclude-from, one
// per line. Blank lines are ignored. There is no comment syntax, because a
// file name can begin with '#'.
func gatherExcludes(o *Options) ([]string, error) {
	out := append([]string(nil), o.Exclude...)
	if o.ExcludeFrom == "" {
		return out, nil
	}
	data, err := os.ReadFile(o.ExcludeFrom)
	if err != nil {
		return nil, fmt.Errorf("reading -X %s: %w", o.ExcludeFrom, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimRight(line, "\r"); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// gatherPaths merges the positional paths with -T/--files-from.
func gatherPaths(o *Options) ([]string, error) {
	paths := append([]string(nil), o.Args...)

	if o.FilesFrom != "" {
		var data []byte
		var err error
		if o.FilesFrom == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(o.FilesFrom)
		}
		if err != nil {
			return nil, fmt.Errorf("reading -T %s: %w", o.FilesFrom, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimRight(line, "\r"); line != "" {
				paths = append(paths, line)
			}
		}
	}

	if len(paths) == 0 {
		return nil, &UsageError{errors.New("no paths to archive")}
	}
	return paths, nil
}

// longLine renders one member of the long listing (doc/design.md 10.9): type
// and mode, owner, size, stored size, percentage saved, codec, time and path,
// with a link's target where it has one. detail (-vv) adds the chunk count,
// whether the member is sealed, and the start of its digest.
//
// A member with no blob of its own - a directory, a link, a device - shows
// "-" for what describes a blob. A hardlink is one of those: it shares the
// blob of its target.
func longLine(l *archive.Listing, m *format.Member, detail bool) string {
	return strings.Join(longColumns(l, m, detail), "  ")
}

// longColumns is longLine as separate cells, for a listing that aligns them.
func longColumns(l *archive.Listing, m *format.Member, detail bool) []string {
	name := m.Path
	switch m.Type {
	case format.TypeSymlink:
		name += " -> " + m.LinkTarget
	case format.TypeHardlink:
		name += " link to " + l.HardlinkTarget(m)
	}
	if m.Data != 0 {
		// The owner can be the file's own earlier version, which -u
		// replaced, or a file since deleted: say so, rather than name a
		// path that the listing does not show, or the file itself.
		switch path, deleted := l.SameAs(m); {
		case deleted && path == m.Path:
			name += " same as its earlier version"
		case deleted:
			name += " same as deleted " + path
		default:
			name += " same as " + path
		}
	}
	size := strconv.FormatUint(m.Size, 10)
	if m.Type == format.TypeCharDev || m.Type == format.TypeBlockDev {
		size = fmt.Sprintf("%d,%d", m.RDev[0], m.RDev[1])
	}

	stored, saved, codecCol := "-", "-", "-"
	chunks, sealed, digest := "-", "-", "-"
	if m.Data != 0 {
		// It stores nothing: the blob is its owner's (doc/design.md 4.3).
		// The digest stays, so that equal content shows as equal.
		digest = hex.EncodeToString(m.Digest[:8])
	} else if m.Type.HasPayload() {
		stored = strconv.FormatUint(m.Length, 10)
		saved = savedPercent(m.PayloadSize(), m.Length)
		if spec, ok := l.Codec(m); ok {
			codecCol = spec.String()
		}
		chunks = strconv.Itoa(len(m.Chunks))
		if m.Enc != nil {
			sealed = "sealed"
		}
		if len(m.Digest) >= 8 {
			digest = hex.EncodeToString(m.Digest[:8])
		}
	}

	cols := []string{modeString(m), owner(m), size, stored, saved, codecCol}
	if detail {
		cols = append(cols, chunks, sealed, digest)
	}
	return append(cols, time.Unix(0, m.MTimeNanos).Format("2006-01-02 15:04:05"), name)
}

// writeTable prints rows with each column padded to its widest cell, two
// spaces apart. The columns in right are aligned on the right. The last column
// is never padded, so a line has no trailing spaces.
//
// Widths count runes, not bytes, so that a name with accents does not push the
// columns after it out of line. East Asian wide characters still do; a path is
// the last column, so that only affects a path in the owner column.
func writeTable(w io.Writer, rows [][]string, right map[int]bool) {
	var widths []int
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], utf8.RuneCountInString(cell))
		}
	}
	var b strings.Builder
	for _, row := range rows {
		b.Reset()
		for i, cell := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			pad := strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell))
			switch {
			case i == len(row)-1:
				b.WriteString(cell)
			case right[i]:
				b.WriteString(pad + cell)
			default:
				b.WriteString(cell + pad)
			}
		}
		fmt.Fprintln(w, b.String())
	}
}

// savedPercent is what compression saved, as unzip -v and gzip -l show it. It
// is below zero when the stored form is larger, as it is for a tiny file whose
// chunk carries a 16-byte tag.
func savedPercent(plain, stored uint64) string {
	if plain == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*(float64(plain)-float64(stored))/float64(plain))
}

// totalsLine sums the listed members for -tvv. Files are the members with a
// blob; a hardlink shares one and adds nothing. The percentage uses the data
// that was stored, so the holes of a sparse file do not count as saved.
func totalsLine(l *archive.Listing) string {
	var files, shared int
	var size, payload, stored, notStored uint64
	for i := range l.Members {
		m := &l.Members[i]
		if !m.Type.HasPayload() {
			continue
		}
		files++
		size += m.Size
		payload += m.PayloadSize()
		stored += m.Length
		if m.Data != 0 {
			shared++
			notStored += l.NotStored(m)
		}
	}
	sharing := ""
	if shared > 0 {
		sharing = fmt.Sprintf(", %d same as another (%d bytes not stored)", shared, notStored)
	}
	return fmt.Sprintf("%d listed, %s, %d bytes stored in %d (%s saved)%s; generation %d, %d tombstoned",
		len(l.Members), plural(files, "file"), size, stored, savedPercent(payload, stored), sharing,
		l.Generation, l.Tombstoned)
}

// plural renders a count with its noun: "1 file", "2 files".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// modeString renders a member's type and mode the way ls does, special bits
// included: s or S for setuid and setgid, t or T for sticky.
func modeString(m *format.Member) string {
	kinds := map[format.MemberType]byte{
		format.TypeDir: 'd', format.TypeSymlink: 'l', format.TypeHardlink: 'h',
		format.TypeFIFO: 'p', format.TypeSocket: 's',
		format.TypeCharDev: 'c', format.TypeBlockDev: 'b',
	}
	b := []byte("----------")
	if k, ok := kinds[m.Type]; ok {
		b[0] = k
	}
	const rwx = "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if m.Mode&(1<<uint(8-i)) != 0 {
			b[i+1] = rwx[i]
		}
	}
	special := func(pos int, bit uint32, set, unset byte) {
		if m.Mode&bit == 0 {
			return
		}
		if b[pos] == 'x' {
			b[pos] = set
		} else {
			b[pos] = unset
		}
	}
	special(3, 0o4000, 's', 'S')
	special(6, 0o2000, 's', 'S')
	special(9, 0o1000, 't', 'T')
	return string(b)
}

// owner renders the recorded owner by name where there is one, by number
// otherwise, and as "-" when --no-owner recorded none.
func owner(m *format.Member) string {
	if m.UID == nil || m.GID == nil {
		return "-"
	}
	user := m.Uname
	if user == "" {
		user = strconv.FormatUint(uint64(*m.UID), 10)
	}
	group := m.Gname
	if group == "" {
		group = strconv.FormatUint(uint64(*m.GID), 10)
	}
	return user + "/" + group
}

// jsonMember is the listing record.
//
// A POSIX path is a byte sequence, and this program deliberately archives ones
// that are not valid UTF-8 (doc/design.md 5.3). JSON strings must be valid
// UTF-8, so such a path cannot be represented faithfully in "path": Go's
// encoder substitutes U+FFFD. PathBase64 carries the exact bytes alongside it,
// and is present only when it is needed, so ordinary listings stay clean.
type jsonMember struct {
	Path       string   `json:"path"`
	PathBase64 string   `json:"path_base64,omitempty"`
	Type       string   `json:"type"`
	Size       uint64   `json:"size"`
	Mode       uint32   `json:"mode"`
	MTime      string   `json:"mtime"`
	Target     string   `json:"target,omitempty"`
	LinkTo     string   `json:"hardlink_to,omitempty"`
	SameAs     string   `json:"same_as,omitempty"` // the member whose content it shares
	SameAsDead bool     `json:"same_as_deleted,omitempty"`
	UID        *uint32  `json:"uid,omitempty"`
	GID        *uint32  `json:"gid,omitempty"`
	Uname      string   `json:"uname,omitempty"`
	Gname      string   `json:"gname,omitempty"`
	RDev       []uint32 `json:"rdev,omitempty"`
	Sparse     bool     `json:"sparse,omitempty"`
	Xattrs     []string `json:"xattrs,omitempty"` // names only: values can be binary

	// What the blob holds, for a member that has one (doc/design.md 10.9).
	// The pointers are set for every such member, so that an empty file
	// reports 0 and a plaintext one false, rather than leaving them out.
	Codec      *jsonCodec `json:"codec,omitempty"`
	StoredSize *uint64    `json:"stored_size,omitempty"`
	Chunks     *int       `json:"chunks,omitempty"`
	Encrypted  *bool      `json:"encrypted,omitempty"`
	Digest     string     `json:"digest,omitempty"` // BLAKE3-256 of the content, hex
}

// jsonCodec is a catalog entry: the codec and the settings it ran with.
type jsonCodec struct {
	Name   string         `json:"name"`
	Params map[string]any `json:"params,omitempty"`
}

func writeJSONList(w io.Writer, l *archive.Listing) error {
	out := make([]jsonMember, 0, len(l.Members))
	for i := range l.Members {
		m := &l.Members[i]
		rec := jsonMember{
			Path:   m.Path,
			Type:   string(m.Type),
			Size:   m.Size,
			Mode:   m.Mode,
			MTime:  time.Unix(0, m.MTimeNanos).UTC().Format(time.RFC3339Nano),
			Target: m.LinkTarget,
			UID:    m.UID, GID: m.GID, Uname: m.Uname, Gname: m.Gname,
			RDev:   m.RDev,
			Sparse: len(m.Sparse) > 0,
		}
		if m.Type == format.TypeHardlink {
			rec.LinkTo = l.HardlinkTarget(m)
		}
		if m.Data != 0 {
			var none uint64
			rec.SameAs, rec.SameAsDead = l.SameAs(m)
			rec.StoredSize = &none
			rec.Digest = hex.EncodeToString(m.Digest)
		} else if m.Type.HasPayload() {
			if spec, ok := l.Codec(m); ok {
				rec.Codec = &jsonCodec{Name: spec.Name, Params: spec.Params}
			}
			stored, chunks, sealed := m.Length, len(m.Chunks), m.Enc != nil
			rec.StoredSize, rec.Chunks, rec.Encrypted = &stored, &chunks, &sealed
			rec.Digest = hex.EncodeToString(m.Digest)
		}
		for name := range m.Xattrs {
			rec.Xattrs = append(rec.Xattrs, name)
		}
		sort.Strings(rec.Xattrs)
		if !utf8.ValidString(m.Path) {
			rec.PathBase64 = base64.StdEncoding.EncodeToString([]byte(m.Path))
		}
		out = append(out, rec)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// partialError reports that the operation finished with some members failing,
// which is exit code 1 rather than an outright failure.
type partialError struct{ failed int }

func (e *partialError) Error() string {
	return fmt.Sprintf("%d member(s) failed; the archive is otherwise complete", e.failed)
}
