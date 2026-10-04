package cli

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/pflag"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
)

// Operation is the single action a run performs. Exactly one is selected per
// invocation (doc/design.md 10.1).
type Operation int

const (
	OpNone Operation = iota
	OpCreate
	OpAppend
	OpList
	OpExtract
	OpUpdate
	OpDelete
	OpCompact
	OpVerify
	OpRepair
	OpInfo
	OpListCodecs
	OpChangePassphrase
	OpDiff
)

var operationNames = map[Operation]string{
	OpNone:       "none",
	OpCreate:     "--create",
	OpAppend:     "--append",
	OpList:       "--list",
	OpExtract:    "--extract",
	OpUpdate:     "--update",
	OpDelete:     "--delete",
	OpCompact:    "--compact",
	OpVerify:     "--verify",
	OpRepair:     "--repair",
	OpInfo:       "--info",
	OpListCodecs: "--list-codecs",

	OpChangePassphrase: "--change-passphrase",
	OpDiff:             "--diff",
}

func (o Operation) String() string {
	if n, ok := operationNames[o]; ok {
		return n
	}
	return fmt.Sprintf("Operation(%d)", int(o))
}

// NeedsArchive reports whether the operation requires -f.
func (o Operation) NeedsArchive() bool { return o != OpListCodecs && o != OpNone }

// WritesArchive reports whether the operation modifies the archive, which
// decides whether it is opened for writing and whether a passphrase is needed
// to add members.
func (o Operation) WritesArchive() bool {
	switch o {
	case OpCreate, OpAppend, OpUpdate, OpDelete, OpCompact, OpRepair, OpChangePassphrase:
		return true
	}
	return false
}

// Limits on the tuning options, so that a typo costs an error rather than the
// machine's memory.
const (
	// MaxWorkers is an upper bound on -j. Beyond this the goroutines cost
	// more than they earn, and a mistyped -j 100000000 should be refused
	// rather than attempted.
	MaxWorkers = 1024
	// MinChunkSize keeps the per-chunk bookkeeping from dominating the data.
	MinChunkSize = 512
)

// The values --update-mode and --on-conflict accept. The archive package
// defines them, because it is what acts on them.
var (
	updateModes      = []string{archive.UpdateNewer, archive.UpdateDifferent, archive.UpdateDigest}
	conflictPolicies = []string{archive.ConflictReplace, archive.ConflictSkip, archive.ConflictError}
)

// Overwrite policies for extraction.
const (
	OverwriteAlways = "overwrite"
	OverwriteNever  = "keep-existing"
	OverwriteNewer  = "newer-only"
)

// Options is the fully resolved configuration for one run: command line,
// environment and configuration file already merged.
type Options struct {
	Op   Operation
	Args []string // paths to archive, or patterns to match

	Archive string
	Chdir   []string

	// Destination is -d: where to unpack. Extraction only, and unlike -C it
	// is created when it does not exist.
	Destination string

	Compress   CompressSpec
	Encrypt    bool
	EncryptIdx bool

	PassphraseFile string
	PassphraseEnv  string
	// NewPassphraseFile and NewPassphraseEnv give the new passphrase of
	// --change-passphrase.
	NewPassphraseFile string
	NewPassphraseEnv  string

	KDFTime    uint32
	KDFMemory  uint32 // KiB
	KDFThreads uint8

	Workers        int
	ChunkSize      Size
	MemoryLimit    Size
	SpillThreshold Size

	FilesFrom   string
	Exclude     []string
	ExcludeFrom string
	// Regex and ExcludeRegex are -R and --exclude-regex (doc/design.md
	// 10.11). validate compiles them into regex and excludeRegex.
	Regex        []string
	ExcludeRegex []string
	regex        fsutil.Regexps
	excludeRegex fsutil.Regexps

	Dereference   bool
	OneFileSystem bool
	NoDedup       bool

	PreservePermissions bool
	PreserveOwner       bool
	PreserveDevices     bool
	NoXattrs            bool
	NoACLs              bool
	NoOwner             bool

	Overwrite  string
	ToStdout   bool
	UpdateMode string
	OnConflict string

	KeepGoing bool
	// DryRun is -n: show what the operation would write, and write nothing
	// (doc/design.md 9.9).
	DryRun     bool
	Long       bool
	JSON       bool
	Quick      bool
	Recompress string

	Verbose  int
	Quiet    bool
	Progress bool

	Config     string
	NoConfig   bool
	ShowConfig bool

	Version bool
	Help    bool

	// explicit records the long names the user actually gave, which is how
	// Unbuilt tells "the default happens to be this" from "the user asked
	// for this".
	explicit map[string]bool

	// The configuration layer (doc/design.md 11). sources says where each
	// value from a configuration file or the environment came from;
	// codecDefaults holds the [codec.NAME] and EICTAR_CODEC_* defaults;
	// configFile is the file read, or "".
	sources       map[string]string
	codecDefaults map[string]map[string]string
	configFile    string
	flags         *pflag.FlagSet // for --show-config
}

// Defaults returns the built-in settings: the lowest-precedence layer, before
// the configuration file, the environment or the command line.
func Defaults() Options {
	return Options{
		Compress:       CompressSpec{Name: "zstd"},
		Workers:        defaultWorkers(runtime.GOMAXPROCS(0)),
		ChunkSize:      4 << 20,
		SpillThreshold: 32 << 20,
		KDFTime:        crypt.DefaultKDFParams.Time,
		KDFMemory:      crypt.DefaultKDFParams.Memory,
		KDFThreads:     crypt.DefaultKDFParams.Threads,
		Overwrite:      OverwriteAlways,
		UpdateMode:     archive.UpdateNewer,
		OnConflict:     archive.ConflictReplace,
	}
}

// defaultWorkers is the default -j for a machine with cpus CPUs: three
// quarters of them, rounded down, and at least one. The other quarter stays
// free for the reader, the emitter and the rest of the machine: 1 and 2 CPUs
// give 1 worker, 3 give 2, 4 give 3 and 8 give 6.
func defaultWorkers(cpus int) int {
	return max(1, cpus*3/4)
}

// flagSet builds the parser. Every short option has a long form, and short
// options bundle, per doc/design.md section 10.
func (o *Options) flagSet(name string) (*pflag.FlagSet, *operationFlags) {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	fs.SortFlags = false
	fs.Usage = func() {} // the caller prints usage; pflag must not write on error

	ops := &operationFlags{}
	fs.BoolVarP(&ops.create, "create", "c", false, "create a new archive")
	fs.BoolVarP(&ops.append_, "append", "r", false, "append to an existing archive")
	fs.BoolVarP(&ops.list, "list", "t", false, "list the archive contents")
	fs.BoolVarP(&ops.extract, "extract", "x", false, "extract members")
	fs.BoolVarP(&ops.update, "update", "u", false, "append only what is out of date")
	fs.BoolVar(&ops.delete_, "delete", false, "tombstone matching members")
	fs.BoolVar(&ops.compact, "compact", false, "reclaim space from tombstoned members")
	fs.BoolVar(&ops.verify, "verify", false, "check integrity without extracting")
	fs.BoolVar(&ops.diff, "diff", false, "compare the archive with the files on disk")
	fs.BoolVar(&ops.repair, "repair", false, "recover from a damaged trailer")
	fs.BoolVar(&ops.info, "info", false, "print archive information")
	fs.BoolVar(&ops.listCodecs, "list-codecs", false, "list compression codecs and their parameters")
	fs.BoolVar(&ops.changePassphrase, "change-passphrase", false, "seal the archive's key under a new passphrase")

	fs.StringVarP(&o.Archive, "file", "f", o.Archive, "the archive to operate on")
	fs.StringArrayVarP(&o.Chdir, "directory", "C", nil, "change to this directory first")
	fs.StringVarP(&o.Destination, "destination", "d", "", "unpack into this directory, creating it if needed (extract only)")

	var compress, chunk, memLimit, spill string
	fs.StringVarP(&compress, "compress", "Z", o.Compress.String(), "compression spec: NAME[:k=v,...] or none")
	// The shorthand must be given at registration: pflag builds its shorthand
	// map there, so setting Flag.Shorthand afterwards registers nothing.
	fs.BoolVarP(&ops.gzip, "gzip", "z", false, "shorthand for --compress gzip")
	fs.BoolVarP(&ops.xz, "xz", "J", false, "shorthand for --compress xz")
	fs.BoolVar(&ops.zstd, "zstd", false, "shorthand for --compress zstd")

	fs.BoolVarP(&o.Encrypt, "encrypt", "e", o.Encrypt, "encrypt the archive")
	fs.BoolVar(&o.EncryptIdx, "encrypt-index", o.EncryptIdx, "also encrypt the index")
	fs.StringVar(&o.PassphraseFile, "passphrase-file", "", "read the passphrase from the first line of this file")
	fs.StringVar(&o.PassphraseEnv, "passphrase-env", "", "read the passphrase from this environment variable")
	fs.StringVar(&o.NewPassphraseFile, "new-passphrase-file", "", "with --change-passphrase, read the new passphrase from this file")
	fs.StringVar(&o.NewPassphraseEnv, "new-passphrase-env", "", "with --change-passphrase, read the new passphrase from this variable")
	fs.Uint32Var(&o.KDFTime, "kdf-time", o.KDFTime, "Argon2id iterations")
	fs.Uint32Var(&o.KDFMemory, "kdf-memory", o.KDFMemory, "Argon2id memory in KiB")
	fs.Uint8Var(&o.KDFThreads, "kdf-threads", o.KDFThreads, "Argon2id parallelism")

	fs.IntVarP(&o.Workers, "workers", "j", o.Workers, "worker count")
	fs.StringVar(&chunk, "chunk-size", o.ChunkSize.String(), "plaintext chunk size")
	fs.StringVar(&memLimit, "memory-limit", o.MemoryLimit.String(), "buffer budget")
	fs.StringVar(&spill, "spill-threshold", o.SpillThreshold.String(), "spill a member buffer to disk past this size")

	fs.StringVarP(&o.FilesFrom, "files-from", "T", "", "read paths from this file, - for stdin")
	fs.StringArrayVar(&o.Exclude, "exclude", nil, "exclude paths matching this glob")
	fs.StringVarP(&o.ExcludeFrom, "exclude-from", "X", "", "read exclude globs from this file")
	fs.StringArrayVarP(&o.Regex, "regex", "R", nil, "keep only paths that this regular expression matches in full")
	fs.StringArrayVar(&o.ExcludeRegex, "exclude-regex", nil, "exclude paths that this regular expression matches in full")

	fs.BoolVarP(&o.Dereference, "dereference", "h", false, "follow symlinks instead of storing them")
	fs.BoolVar(&o.OneFileSystem, "one-file-system", false, "do not cross mount points")
	fs.BoolVar(&o.NoDedup, "no-dedup", false, "store each copy of the same content in full")

	fs.BoolVarP(&o.PreservePermissions, "preserve-permissions", "p", false, "restore modes exactly, special bits, ACLs, and privileged xattrs as root")
	fs.BoolVar(&o.PreserveOwner, "preserve-owner", false, "restore uid and gid (needs root)")
	fs.BoolVar(&o.PreserveDevices, "preserve-devices", false, "recreate device nodes (needs root)")
	fs.BoolVar(&o.NoXattrs, "no-xattrs", false, "do not store or restore extended attributes")
	fs.BoolVar(&o.NoACLs, "no-acls", false, "do not store or restore ACLs")
	fs.BoolVar(&o.NoOwner, "no-owner", false, "do not store ownership")

	fs.BoolVarP(&ops.keepExisting, "keep-existing", "k", false, "never overwrite an existing file")
	fs.BoolVar(&ops.overwrite, "overwrite", false, "overwrite existing files (the default)")
	fs.BoolVar(&ops.newerOnly, "newer-only", false, "overwrite only when the member is newer")
	fs.BoolVarP(&o.ToStdout, "to-stdout", "O", false, "write extracted content to stdout")

	fs.StringVar(&o.UpdateMode, "update-mode", o.UpdateMode, "with -u: newer, different or digest")
	fs.StringVar(&o.OnConflict, "on-conflict", o.OnConflict, "with -r: replace, skip or error")
	fs.BoolVar(&o.KeepGoing, "keep-going", false, "continue past a per-member error")
	fs.BoolVarP(&o.DryRun, "dry-run", "n", false, "show what the operation would write, and write nothing")
	fs.BoolVar(&o.Long, "long", false, "long-format listing")
	fs.BoolVar(&o.JSON, "json", false, "machine-readable listing")
	fs.BoolVar(&o.Quick, "quick", false, "with --verify, check the structure only")
	fs.StringVar(&o.Recompress, "recompress", "", "with --compact, re-encode using this spec")

	fs.CountVarP(&o.Verbose, "verbose", "v", "list members as they are processed")
	fs.BoolVarP(&o.Quiet, "quiet", "q", false, "errors only")
	fs.BoolVar(&o.Progress, "progress", false, "progress meter on stderr")

	fs.StringVar(&o.Config, "config", "", "use this configuration file")
	fs.BoolVar(&o.NoConfig, "no-config", false, "read no configuration file")
	fs.BoolVar(&o.ShowConfig, "show-config", false, "print the effective settings and exit")

	fs.BoolVar(&o.Version, "version", false, "print the version and exit")
	fs.BoolVar(&o.Help, "help", false, "print this help and exit")

	ops.sizes = sizeTargets{
		{"chunk-size", &chunk, &o.ChunkSize},
		{"memory-limit", &memLimit, &o.MemoryLimit},
		{"spill-threshold", &spill, &o.SpillThreshold},
	}
	ops.compress = &compress
	return fs, ops
}

// operationFlags holds the booleans that need post-parse resolution: the
// operation selectors, the compression shorthands and the overwrite policy,
// none of which map one-to-one onto an Options field.
type operationFlags struct {
	create, append_, list, extract, update bool
	delete_, compact, verify, repair, info bool
	listCodecs, changePassphrase, diff     bool
	gzip, xz, zstd                         bool
	keepExisting, overwrite, newerOnly     bool
	compress                               *string
	sizes                                  sizeTargets
}

type sizeTargets []struct {
	name string
	raw  *string
	dst  *Size
}

// unbuiltOptions are options this build parses but does not yet honour, with
// the milestone that brings each.
//
// Accepting one silently would be the quiet wrongness this tool is supposed to
// avoid: --exclude that excludes nothing hands back an archive containing what
// the user meant to leave out, and they would not find out until they read it.
// The same rule the design applies to a misspelled environment variable
// (doc/design.md 11.2) applies here.
var unbuiltOptions = map[string]string{}

// Unbuilt reports the first option the user set that this build ignores.
//
// It is deliberately not part of Parse: parsing and validating a command line
// is one job, and deciding what this build can carry out is another. Keeping
// them apart lets the parser be tested against the whole option surface,
// including the parts not yet wired up.
//
// Options are checked in a fixed order so the message does not depend on map
// iteration.
func (o *Options) Unbuilt() error {
	names := make([]string, 0, len(unbuiltOptions))
	for name := range unbuiltOptions {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if o.explicit[name] {
			return &unimplementedError{
				what:      "--" + name,
				milestone: unbuiltOptions[name],
			}
		}
	}
	return nil
}

// Parse turns a command line into resolved Options. It reports a usage error
// for anything it cannot make sense of, and never partially applies a run.
func Parse(argv []string) (*Options, error) {
	o := Defaults()
	fs, ops := o.flagSet("eictar")

	if err := fs.Parse(argv); err != nil {
		return nil, &UsageError{err}
	}
	o.Args = fs.Args()

	o.explicit = make(map[string]bool)
	fs.Visit(func(f *pflag.Flag) { o.explicit[f.Name] = true })

	// --version and --help short-circuit everything else, including the
	// one-operation rule.
	if o.Version || o.Help {
		return &o, nil
	}

	var err error
	if o.Op, err = resolveOperation(ops); err != nil {
		// --show-config needs no operation: it shows everything.
		if !o.ShowConfig || !noOperation(ops) {
			return nil, err
		}
		o.Op = OpNone
	}

	// The configuration file and the environment fill in what the command
	// line left out. They are read after the operation is known, because a
	// setting that does not apply to it is ignored (doc/design.md 11).
	o.sources = map[string]string{}
	o.codecDefaults = map[string]map[string]string{}
	if o.NoConfig {
		// Nothing but the command line decides: no file, and no EICTAR_*.
	} else {
		l, err := loadLayers(o.Config, o.PassphraseEnv, o.NewPassphraseEnv)
		if err != nil {
			return nil, err
		}
		if err := l.apply(&o, fs); err != nil {
			return nil, err
		}
	}

	if err := resolveCompression(&o, fs, ops); err != nil {
		return nil, err
	}
	o.Compress = o.withCodecDefaults(o.Compress)
	if err := resolveOverwrite(&o, ops); err != nil {
		return nil, err
	}
	for _, s := range ops.sizes {
		v, err := ParseSize(*s.raw)
		if err != nil {
			return nil, &UsageError{fmt.Errorf("--%s: %w", s.name, err)}
		}
		*s.dst = v
	}
	if o.ShowConfig {
		o.flags = fs
		return &o, nil
	}
	if err := o.validate(); err != nil {
		return nil, err
	}
	return &o, nil
}

// noOperation reports that no operation option was given at all.
func noOperation(ops *operationFlags) bool {
	return !(ops.create || ops.append_ || ops.list || ops.extract || ops.update ||
		ops.delete_ || ops.compact || ops.verify || ops.repair || ops.info || ops.listCodecs ||
		ops.changePassphrase || ops.diff)
}

func resolveOperation(ops *operationFlags) (Operation, error) {
	selected := []struct {
		on bool
		op Operation
	}{
		{ops.create, OpCreate},
		{ops.append_, OpAppend},
		{ops.list, OpList},
		{ops.extract, OpExtract},
		{ops.update, OpUpdate},
		{ops.delete_, OpDelete},
		{ops.compact, OpCompact},
		{ops.verify, OpVerify},
		{ops.diff, OpDiff},
		{ops.repair, OpRepair},
		{ops.info, OpInfo},
		{ops.listCodecs, OpListCodecs},
		{ops.changePassphrase, OpChangePassphrase},
	}

	var found []Operation
	for _, s := range selected {
		if s.on {
			found = append(found, s.op)
		}
	}
	switch len(found) {
	case 0:
		return OpNone, &UsageError{fmt.Errorf("no operation selected: one of -c, -r, -t, -x, -u, --delete, --compact, --change-passphrase, --verify, --diff, --repair, --info or --list-codecs is required")}
	case 1:
		return found[0], nil
	default:
		return OpNone, &UsageError{fmt.Errorf("only one operation may be given, got %v and %v", found[0], found[1])}
	}
}

func resolveCompression(o *Options, fs *pflag.FlagSet, ops *operationFlags) error {
	shorthands := []struct {
		on   bool
		name string
		flag string
	}{
		{ops.gzip, "gzip", "-z"},
		{ops.xz, "xz", "-J"},
		{ops.zstd, "zstd", "--zstd"},
	}

	var chosen []string
	for _, s := range shorthands {
		if s.on {
			chosen = append(chosen, s.flag)
			o.Compress = CompressSpec{Name: s.name}
		}
	}
	if len(chosen) > 1 {
		return &UsageError{fmt.Errorf("%s and %s select different codecs", chosen[0], chosen[1])}
	}
	if fs.Changed("compress") {
		if len(chosen) > 0 {
			return &UsageError{fmt.Errorf("--compress and %s select different codecs", chosen[0])}
		}
		spec, err := ParseCompressSpec(*ops.compress)
		if err != nil {
			return &UsageError{fmt.Errorf("--compress: %w", err)}
		}
		o.Compress = spec
	}
	return nil
}

func resolveOverwrite(o *Options, ops *operationFlags) error {
	var chosen []string
	if ops.keepExisting {
		chosen = append(chosen, "--keep-existing")
		o.Overwrite = OverwriteNever
	}
	if ops.newerOnly {
		chosen = append(chosen, "--newer-only")
		o.Overwrite = OverwriteNewer
	}
	if ops.overwrite {
		chosen = append(chosen, "--overwrite")
		o.Overwrite = OverwriteAlways
	}
	if len(chosen) > 1 {
		return &UsageError{fmt.Errorf("%s and %s are mutually exclusive", chosen[0], chosen[1])}
	}
	return nil
}

// expectsEncryption reports whether the user told us, by supplying a
// passphrase source, that the archive should be encrypted. Reading a
// plaintext archive in that case is refused: it is how a stripped or
// substituted archive is caught (doc/design.md 14.4).
func (o *Options) expectsEncryption() bool {
	return o.PassphraseFile != "" || o.PassphraseEnv != ""
}

// validate applies the cross-option rules. Each one exists because the
// alternative is a run that does something other than what was asked.
func (o *Options) validate() error {
	if o.Op.NeedsArchive() && o.Archive == "" {
		return &UsageError{fmt.Errorf("%v requires -f ARCHIVE", o.Op)}
	}
	if o.Archive == "-" {
		return &UsageError{fmt.Errorf("the archive cannot be a pipe: the index is at the end of the file and must be seekable")}
	}
	if o.Workers < 1 || o.Workers > MaxWorkers {
		return &UsageError{fmt.Errorf("--workers must be between 1 and %d, got %d",
			MaxWorkers, o.Workers)}
	}
	if o.Quiet && o.Verbose > 0 {
		return &UsageError{fmt.Errorf("--quiet and --verbose are mutually exclusive")}
	}
	if o.PassphraseFile != "" && o.PassphraseEnv != "" {
		return &UsageError{fmt.Errorf("--passphrase-file and --passphrase-env are mutually exclusive")}
	}
	if o.NewPassphraseFile != "" && o.NewPassphraseEnv != "" {
		return &UsageError{fmt.Errorf("--new-passphrase-file and --new-passphrase-env are mutually exclusive")}
	}
	if o.Op != OpChangePassphrase {
		for _, name := range []string{"new-passphrase-file", "new-passphrase-env"} {
			if o.explicit[name] {
				return &UsageError{fmt.Errorf("--%s applies to --change-passphrase only", name)}
			}
		}
	}
	if o.Config != "" && o.NoConfig {
		return &UsageError{fmt.Errorf("--config and --no-config are mutually exclusive")}
	}

	if o.Destination != "" {
		if o.Op != OpExtract {
			return &UsageError{fmt.Errorf("-d/--destination applies to -x only; use -C to change directory for %v", o.Op)}
		}
		if len(o.Chdir) > 0 {
			// Both name where the work happens. Silently letting one win
			// would unpack somewhere the user did not choose.
			return &UsageError{fmt.Errorf("-d/--destination and -C/--directory are mutually exclusive")}
		}
	}
	if o.ToStdout && o.Destination != "" {
		return &UsageError{fmt.Errorf("-O/--to-stdout writes to standard output, so -d/--destination has nothing to do")}
	}

	if !containsString(updateModes, o.UpdateMode) {
		return &UsageError{fmt.Errorf("--update-mode must be one of %v, got %q", updateModes, o.UpdateMode)}
	}
	if o.Op != OpUpdate && o.explicit["update-mode"] {
		return &UsageError{fmt.Errorf("--update-mode applies to -u only")}
	}
	if !containsString(conflictPolicies, o.OnConflict) {
		return &UsageError{fmt.Errorf("--on-conflict must be one of %v, got %q", conflictPolicies, o.OnConflict)}
	}
	if o.Op != OpAppend && o.explicit["on-conflict"] {
		return &UsageError{fmt.Errorf("--on-conflict applies to -r only")}
	}
	if o.Quick && o.Op != OpVerify {
		return &UsageError{fmt.Errorf("--quick applies to --verify only")}
	}
	if o.DryRun {
		if !containsOp(dryRunOps, o.Op) {
			return &UsageError{fmt.Errorf("-n/--dry-run applies to -c, -r, -u, -x and --delete only")}
		}
		// A dry run reads almost nothing, so a meter has nothing to show.
		// Typed, asking for both is a mistake; from a configuration, it is
		// a preference for the runs that do work.
		if o.Progress {
			if o.explicit["progress"] {
				return &UsageError{fmt.Errorf("--progress has nothing to show in a dry run (-n)")}
			}
			o.Progress = false
		}
	}
	if o.EncryptIdx && !o.Encrypt {
		// Typed, it is a mistake. From a configuration, it is a preference
		// for when an archive is encrypted, and this one is not.
		if o.explicit["encrypt-index"] {
			return &UsageError{fmt.Errorf("--encrypt-index requires --encrypt")}
		}
		o.EncryptIdx = false
	}

	// Metadata options have one meaning each, on the operations where they
	// mean anything. Elsewhere they would be silently ignored, which this
	// program does not do (doc/design.md 10.6).
	scoped := []struct {
		name string
		ops  []Operation
	}{
		{"one-file-system", walking},
		{"dereference", walking},
		{"no-dedup", adding},
		{"preserve-permissions", []Operation{OpExtract}},
		{"preserve-owner", []Operation{OpExtract}},
		{"preserve-devices", []Operation{OpExtract}},
		{"no-owner", append([]Operation{OpExtract}, walking...)},
		{"no-xattrs", append([]Operation{OpExtract}, walking...)},
		{"no-acls", append([]Operation{OpExtract}, walking...)},
		{"exclude", append([]Operation{OpList, OpExtract}, walking...)},
		{"exclude-from", append([]Operation{OpList, OpExtract}, walking...)},
		{"exclude-regex", append([]Operation{OpList, OpExtract}, walking...)},
		{"regex", append([]Operation{OpList, OpExtract, OpVerify, OpDelete}, walking...)},
	}
	for _, sc := range scoped {
		if o.explicit[sc.name] && !containsOp(sc.ops, o.Op) {
			return &UsageError{fmt.Errorf("--%s does not apply to %v", sc.name, o.Op)}
		}
	}
	var err error
	if o.regex, err = fsutil.CompileRegexps(o.Regex); err != nil {
		return &UsageError{fmt.Errorf("-R: %w", err)}
	}
	if o.excludeRegex, err = fsutil.CompileRegexps(o.ExcludeRegex); err != nil {
		return &UsageError{fmt.Errorf("--exclude-regex: %w", err)}
	}

	// chown and mknod need root. Refusing up front says so once; letting
	// the run try would fail every member in turn with the same error.
	if (o.PreserveOwner || o.PreserveDevices) && !isRoot() {
		opt := "--preserve-owner"
		if !o.PreserveOwner {
			opt = "--preserve-devices"
		}
		return &UsageError{fmt.Errorf("%s needs root: only root can change ownership or create device nodes", opt)}
	}

	// Encryption is decided when an archive is created; afterwards the
	// archive's own header says how it was made. Accepting these elsewhere
	// would let someone believe they had chosen something they had not. The
	// one exception is the key derivation, which a change of passphrase sets
	// again (doc/design.md 9.7).
	for _, name := range []string{"encrypt", "encrypt-index", "kdf-time", "kdf-memory", "kdf-threads"} {
		if !o.explicit[name] || o.Op == OpCreate {
			continue
		}
		if o.Op == OpChangePassphrase && strings.HasPrefix(name, "kdf-") {
			continue
		}
		return &UsageError{fmt.Errorf("--%s applies to -c only: an existing archive's "+
			"encryption is fixed by its header", name)}
	}
	if o.KDFTime < 1 || o.KDFTime > format.MaxKDFTime {
		return &UsageError{fmt.Errorf("--kdf-time must be between 1 and %d, got %d",
			format.MaxKDFTime, o.KDFTime)}
	}
	if o.KDFMemory > format.MaxKDFMemoryKiB {
		return &UsageError{fmt.Errorf("--kdf-memory must be at most %d KiB, got %d",
			format.MaxKDFMemoryKiB, o.KDFMemory)}
	}
	if o.Recompress != "" {
		if o.Op != OpCompact {
			return &UsageError{fmt.Errorf("--recompress applies to --compact only")}
		}
		if _, err := ParseCompressSpec(o.Recompress); err != nil {
			return &UsageError{fmt.Errorf("--recompress: %w", err)}
		}
	}
	// The lower bound keeps the per-chunk overhead sane; the upper one is the
	// format's own limit, which exists because a reader allocates a buffer of
	// this size (format.MaxChunkSize).
	if o.ChunkSize < MinChunkSize || o.ChunkSize > Size(format.MaxChunkSize) {
		return &UsageError{fmt.Errorf("--chunk-size must be between %s and %s, got %s",
			Size(MinChunkSize), Size(format.MaxChunkSize), o.ChunkSize)}
	}

	// An operation that reads patterns must not be handed filesystem paths by
	// mistake, and one that reads paths needs at least one unless the list
	// comes from a file.
	switch o.Op {
	case OpCreate, OpAppend, OpUpdate:
		if len(o.Args) == 0 && o.FilesFrom == "" {
			return &UsageError{fmt.Errorf("%v needs at least one path, or -T FILE", o.Op)}
		}
	case OpDelete:
		if len(o.Args) == 0 && len(o.Regex) == 0 {
			return &UsageError{fmt.Errorf("--delete needs at least one pattern, or -R")}
		}
	case OpCompact, OpChangePassphrase, OpInfo, OpRepair, OpListCodecs:
		if len(o.Args) > 0 {
			return &UsageError{fmt.Errorf("%v takes no positional arguments, got %d", o.Op, len(o.Args))}
		}
	}
	return nil
}

func containsOp(ops []Operation, op Operation) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}

// isRoot is a variable so that tests can exercise the root-only options.
var isRoot = func() bool { return os.Geteuid() == 0 }

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
