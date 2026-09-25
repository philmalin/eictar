package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
)

// openFor builds the open options every operation on an existing archive
// uses: ask for the passphrase only if the archive needs one, and refuse a
// plaintext archive when a passphrase source was given.
func openFor(o *Options, rep *reporter) archive.OpenOptions {
	return archive.OpenOptions{
		Passphrase:        askFor(o, rep),
		RequireEncryption: o.expectsEncryption(),
	}
}

// runAppend is -r and -u (doc/design.md 9.2 and 10.5).
func runAppend(o *Options, stdout, stderr io.Writer) error {
	if err := checkCompress(o, stderr); err != nil {
		return err
	}
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	cfg, err := addConfig(o, rep)
	if err != nil {
		return err
	}

	acfg := archive.AppendConfig{CreateConfig: cfg, Open: openFor(o, rep)}
	if o.Op == OpUpdate {
		acfg.UpdateMode = o.UpdateMode
	} else {
		acfg.OnConflict = o.OnConflict
	}

	var done func()
	acfg.Reporter, done = withProgress(o, rep, stderr)
	stats, err := archive.AppendArchive(acfg)
	done()
	if err != nil {
		return err
	}
	if stats.Failed > 0 {
		return &partialError{failed: stats.Failed}
	}
	return nil
}

func runDelete(o *Options, stdout, stderr io.Writer) error {
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	_, err := archive.DeleteMembers(archive.DeleteConfig{
		Archive:  o.Archive,
		Patterns: o.Args,
		Regex:    o.regex,
		Open:     openFor(o, rep),
		Reporter: rep,
	})
	return err
}

func runCompact(o *Options, stdout, stderr io.Writer) error {
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	cfg := archive.CompactConfig{
		Archive:  o.Archive,
		Open:     openFor(o, rep),
		Reporter: rep,
	}
	if o.Recompress != "" {
		// validate has parsed the spec already; the encoder checks its
		// parameters here, before the archive is touched.
		spec, err := ParseCompressSpec(o.Recompress)
		if err != nil {
			return &UsageError{fmt.Errorf("--recompress: %w", err)}
		}
		spec = o.withCodecDefaults(spec)
		if err := checkSpec(o, spec, "--recompress", stderr); err != nil {
			return err
		}
		cfg.Recompress = &archive.RecompressConfig{
			Codec:          spec.Name,
			Params:         codec.Params(spec.Params),
			ChunkSize:      int(o.ChunkSize),
			Workers:        o.Workers,
			MemoryLimit:    int64(o.MemoryLimit),
			SpillThreshold: int64(o.SpillThreshold),
		}
	}
	var done func()
	cfg.Reporter, done = withProgress(o, rep, stderr)
	res, err := archive.CompactArchive(cfg)
	done()
	if err != nil || o.Quiet {
		return err
	}
	if res.NothingToDo {
		fmt.Fprintf(stdout, "%s: nothing to compact\n", o.Archive)
		return nil
	}
	if cfg.Recompress != nil {
		fmt.Fprintf(stdout, "%s: %s encoded again with %s; %d -> %d bytes, %d tombstones removed\n",
			o.Archive, plural(res.Recompressed, "member"), o.Recompress, res.OldSize, res.NewSize, res.Dropped)
		return nil
	}
	fmt.Fprintf(stdout, "%s: %d bytes reclaimed (%d -> %d), %d tombstones removed\n",
		o.Archive, res.OldSize-res.NewSize, res.OldSize, res.NewSize, res.Dropped)
	return nil
}

// runChangePassphrase seals the archive's data key under a new passphrase,
// and writes the archive again as compact does (doc/design.md 9.7). Only the
// --kdf-* options typed on this command line change the key derivation.
// Otherwise the archive keeps its own parameters, not the defaults.
func runChangePassphrase(o *Options, stdout, stderr io.Writer) error {
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	var params crypt.KDFParams
	if o.explicit["kdf-time"] {
		params.Time = o.KDFTime
	}
	if o.explicit["kdf-memory"] {
		params.Memory = o.KDFMemory
	}
	if o.explicit["kdf-threads"] {
		params.Threads = o.KDFThreads
	}
	newSrc := passphraseSource{file: o.NewPassphraseFile, env: o.NewPassphraseEnv, confirm: true, isNew: true}
	cfg := archive.CompactConfig{
		Archive:  o.Archive,
		Open:     openFor(o, rep),
		Reporter: rep,
		Rewrap: &archive.RewrapConfig{
			Params: params,
			Passphrase: func() ([]byte, error) {
				newSrc.warnIfInsecureSource(rep.Warn)
				return newSrc.get()
			},
		},
	}
	var done func()
	cfg.Reporter, done = withProgress(o, rep, stderr)
	res, err := archive.CompactArchive(cfg)
	done()
	if err != nil || o.Quiet {
		return err
	}
	fmt.Fprintf(stdout, "%s: the passphrase is changed; %d -> %d bytes, %d tombstones removed\n",
		o.Archive, res.OldSize, res.NewSize, res.Dropped)
	return nil
}

func runVerify(o *Options, stdout, stderr io.Writer) error {
	// Each damaged member is reported on stderr as it is found, whatever -q
	// says: that report is the purpose of the operation.
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose}
	progress, done := withProgress(o, rep, stderr)
	res, err := archive.VerifyArchive(archive.VerifyConfig{
		Archive:  o.Archive,
		Patterns: o.Args,
		Regex:    o.regex,
		Open:     openFor(o, rep),
		Quick:    o.Quick,
		Reporter: progress,
	})
	done()
	if err != nil || o.Quiet {
		return err
	}
	if o.Quick {
		fmt.Fprintf(stdout, "%s: structure OK (member data not read)\n", o.Archive)
	} else {
		fmt.Fprintf(stdout, "%s: OK, %d members, %d bytes checked\n", o.Archive, res.Checked, res.Bytes)
	}
	return nil
}

func runRepair(o *Options, stdout, stderr io.Writer) error {
	rep := &reporter{out: stdout, errOut: stderr, quiet: o.Quiet}
	res, err := archive.RepairArchive(o.Archive, openFor(o, rep))
	if err != nil || o.Quiet {
		return err
	}
	if res.AlreadyValid {
		fmt.Fprintf(stdout, "%s: the archive is intact; nothing to repair\n", o.Archive)
		return nil
	}
	fmt.Fprintf(stdout, "%s: removed %d bytes; restored generation %d\n", o.Archive, res.Removed, res.Generation)
	return nil
}

func runInfo(o *Options, stdout, stderr io.Writer) error {
	rep := &reporter{errOut: stderr, quiet: o.Quiet}
	in, err := archive.Info(o.Archive, openFor(o, rep))
	if err != nil {
		return err
	}
	writeInfo(stdout, o.Archive, in)
	return nil
}

func writeInfo(w io.Writer, path string, in *archive.ArchiveInfo) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, f string, args ...any) { fmt.Fprintf(tw, "%s:\t"+f+"\n", append([]any{k}, args...)...) }

	row("archive", "%s", path)
	row("format", "%d.%d", in.Header.VersionMajor, in.Header.VersionMinor)
	row("uuid", "%x", in.Header.ArchiveUUID)
	row("created", "%s", time.Unix(0, in.Header.CreatedUnixNanos).UTC().Format(time.RFC3339))
	row("size", "%d bytes", in.Size)
	row("generation", "%d", in.Trailer.Generation)
	if in.Crypto == nil {
		row("encryption", "none")
	} else {
		row("encryption", "XChaCha20-Poly1305, Argon2id time=%d memory=%d KiB threads=%d",
			in.Crypto.Time, in.Crypto.Memory, in.Crypto.Threads)
	}
	switch {
	case in.Trailer.IndexEncrypted():
		row("index", "%d bytes, sealed", in.IndexLength)
	case in.Crypto != nil:
		row("index", "%d bytes, authenticated, not sealed", in.IndexLength)
	default:
		row("index", "%d bytes", in.IndexLength)
	}
	row("members", "%d live, %d tombstoned", in.Live, in.Dead)
	row("content", "%d bytes, stored in %d bytes", in.Plain, in.Blobs)
	row("dead space", "%d bytes (reclaimed by --compact)", in.DeadSpace)

	var codecs []string
	for _, c := range in.Codecs {
		codecs = append(codecs, fmt.Sprintf("%s (%d members)", c.Spec, c.Members))
	}
	if in.Stored > 0 {
		codecs = append(codecs, fmt.Sprintf("none (%d members)", in.Stored))
	}
	if len(codecs) == 0 {
		codecs = []string{"-"}
	}
	row("codecs", "%s", strings.Join(codecs, ", "))
	for _, d := range in.Dicts {
		row("dictionary", "%d: %d bytes, generation %d, %s",
			d.Dict.ID, d.Dict.Size, d.Dict.Generation, plural(d.Members, "live member"))
	}
	tw.Flush()
}
