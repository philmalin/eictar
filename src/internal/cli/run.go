package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
)

// Exit codes (doc/design.md 10.7). Code 3 is kept distinct from code 4 so a
// backup script can tell "this archive is damaged" from "the disk filled up".
const (
	ExitOK       = 0
	ExitPartial  = 1 // finished, but some members failed under --keep-going, or --diff found differences
	ExitUsage    = 2
	ExitCorrupt  = 3 // damaged archive, or authentication failure
	ExitIO       = 4
	ExitInternal = 70 // sysexits EX_SOFTWARE; see notImplemented below
)

// UsageError is a mistake in how the program was invoked, as opposed to a
// failure while doing the work. It maps to ExitUsage.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

// Version is set at build time; the zero value keeps a developer build honest
// about being one.
var Version = "dev"

// version is what --version prints. A binary from `go install ...@v1.0.0`
// has no -ldflags, but the Go toolchain records the module version in it.
func version() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return Version
}

// Run parses argv and performs the requested operation, returning the process
// exit code. It writes nothing to the real standard streams, which is what
// lets the operational tests drive it in-process as well as as a binary.
func Run(argv []string, stdout, stderr io.Writer) int {
	// Run bare, the friendly thing is the full help on stdout, not a one-line
	// complaint on stderr: someone who types the name of a program they have
	// not used before is asking what it does. A wrong command line still gets
	// the terse error, because there the mistake is the useful information.
	if len(argv) == 0 {
		writeUsage(stdout)
		return ExitOK
	}

	opts, err := Parse(argv)
	if err != nil {
		fmt.Fprintf(stderr, "eictar: %v\n", err)
		// The hint helps someone who mistyped; it is noise for someone who
		// asked for a feature that is not built yet.
		var usage *UsageError
		if errors.As(err, &usage) {
			fmt.Fprintf(stderr, "Try 'eictar --help' for more information.\n")
		}
		return exitCodeFor(err)
	}

	switch {
	case opts.Help:
		writeUsage(stdout)
		return ExitOK
	case opts.Version:
		fmt.Fprintf(stdout, "eictar %s\n", version())
		return ExitOK
	case opts.ShowConfig:
		fmt.Fprint(stdout, EffectiveSettings(opts))
		return ExitOK
	}

	// A setting nobody typed can surprise; -v says where they came from
	// (doc/design.md 11.4).
	if opts.Verbose > 0 && opts.configFile != "" {
		fmt.Fprintf(stderr, "eictar: using configuration file %s\n", opts.configFile)
	}

	// Checked after --help and --version, and after Parse has had its say, so
	// that a genuine usage mistake is reported before "not built yet".
	if err := opts.Unbuilt(); err != nil {
		fmt.Fprintf(stderr, "eictar: %v\n", err)
		return exitCodeFor(err)
	}

	if name := archiveName(opts.Op, opts.Archive); name != opts.Archive {
		if opts.Op == OpCreate && !opts.Quiet {
			verb := "creating"
			if opts.DryRun {
				verb = "would create"
			}
			fmt.Fprintf(stderr, "eictar: %s %s\n", verb, name)
		}
		opts.Archive = name
	}

	if err := dispatch(opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "eictar: %v\n", err)
		return exitCodeFor(err)
	}
	return ExitOK
}

// ArchiveExt is the conventional extension of an archive (doc/design.md
// 10.12). The program finds an archive by its magic, not by its name.
const ArchiveExt = ".ect"

// archiveName applies the extension rule of doc/design.md 10.12. Create adds
// .ect to a name with no extension. Every other operation uses the name with
// .ect when no file has the name as typed and that one exists, so that it
// finds what create made. A file with the name as typed always wins. A
// directory does not: `eictar -cf backup backup` makes backup.ect beside the
// directory backup, and -tf backup must find it. A name that is a directory
// counts as one with no extension even when it has a dot, since a directory
// cannot be the archive: -cf v1.5 v1.5 makes v1.5.ect.
func archiveName(op Operation, name string) string {
	if name == "" || strings.HasSuffix(name, "/") ||
		strings.HasSuffix(name, string(filepath.Separator)) {
		return name
	}
	if hasExtension(name) {
		if fi, err := os.Stat(name); err != nil || !fi.IsDir() {
			return name
		}
	}
	if op == OpCreate {
		return name + ArchiveExt
	}
	if !op.NeedsArchive() {
		return name
	}
	if fi, err := os.Stat(name); err == nil && !fi.IsDir() || err != nil && !errors.Is(err, fs.ErrNotExist) {
		return name
	}
	if _, err := os.Stat(name + ArchiveExt); err == nil {
		return name + ArchiveExt
	}
	return name
}

// hasExtension reports whether the last element of a path, without its
// leading dots, has a dot: "a.tar" and "home.2026-09" have one, "backup" and
// ".backup" do not.
func hasExtension(name string) bool {
	base := strings.TrimLeft(filepath.Base(name), ".")
	return strings.Contains(base, ".")
}

// dispatch runs the selected operation.
//
// Every operation is built. notImplemented stays for the options that are
// not (doc/design.md 10.6).
func dispatch(o *Options, stdout, stderr io.Writer) error {
	if o.DryRun {
		return runDryRun(o, stdout, stderr)
	}
	switch o.Op {
	case OpCreate:
		return runCreate(o, stdout, stderr)
	case OpList:
		return runList(o, stdout, stderr)
	case OpExtract:
		return runExtract(o, stdout, stderr)
	case OpListCodecs:
		return runListCodecs(stdout)
	case OpAppend, OpUpdate:
		return runAppend(o, stdout, stderr)
	case OpDelete:
		return runDelete(o, stdout, stderr)
	case OpCompact:
		return runCompact(o, stdout, stderr)
	case OpChangePassphrase:
		return runChangePassphrase(o, stdout, stderr)
	case OpVerify:
		return runVerify(o, stdout, stderr)
	case OpDiff:
		return runDiff(o, stdout, stderr)
	case OpRepair:
		return runRepair(o, stdout, stderr)
	case OpInfo:
		return runInfo(o, stdout, stderr)
	default:
		return fmt.Errorf("internal: unhandled operation %v", o.Op)
	}
}

// unimplementedError covers anything this build parses but cannot do yet: an
// operation, or an option that would change the result if it were honoured.
type unimplementedError struct {
	what      string
	milestone string
}

func (e *unimplementedError) Error() string {
	return fmt.Sprintf("%s is not implemented in this build (scheduled for %s)", e.what, e.milestone)
}

func notImplemented(op Operation, milestone string) error {
	return &unimplementedError{what: op.String(), milestone: milestone}
}

func exitCodeFor(err error) int {
	var usage *UsageError
	if errors.As(err, &usage) {
		return ExitUsage
	}
	var unimpl *unimplementedError
	if errors.As(err, &unimpl) {
		return ExitInternal
	}
	var partial *partialError
	var differ *differError
	if errors.As(err, &partial) || errors.As(err, &differ) {
		return ExitPartial
	}
	// A pattern that matches nothing, and a path that is already in the
	// archive under --on-conflict=error, are mistakes in what was asked for;
	// nothing was changed (doc/design.md 9.2 and 10.7).
	if errors.Is(err, archive.ErrNoMatch) || errors.Is(err, archive.ErrConflict) {
		return ExitUsage
	}
	// A damaged archive is reported separately from an I/O failure, so a
	// backup script can tell "this archive is broken" from "the disk filled
	// up" (doc/design.md 10.7).
	if archive.IsDamage(err) {
		return ExitCorrupt
	}
	for _, untrusted := range []error{
		// Too new for this build, or a member path that would escape.
		format.ErrUnsupportedVersion, fsutil.ErrUnsafePath, archive.ErrUnsafeLink,
		// A wrong passphrase is "this archive did not authenticate", which
		// exit code 3 exists to say, as a failed tag is (doc/design.md 10.7).
		crypt.ErrWrongPassphrase,
		// Expected sealed, found plain: not an I/O problem, a trust one.
		archive.ErrNotEncrypted,
	} {
		if errors.Is(err, untrusted) {
			return ExitCorrupt
		}
	}
	return ExitIO
}

const usageText = `Usage: eictar OPERATION -f ARCHIVE [options] [PATH|PATTERN...]

Operations (exactly one):
  -c, --create              create a new archive
  -r, --append              add paths; a path already there is replaced
  -u, --update              add only the paths that are out of date
  -t, --list                list the members (-v: long listing, -vv: more)
  -x, --extract             extract members
      --delete              mark matching members as deleted
      --compact             write the archive again without dead space
      --change-passphrase   seal the archive's key under a new passphrase
      --verify              check every digest and tag, without extracting
      --diff                compare the members with the files on disk
      --repair              cut the archive back after a crash
      --info                show the settings, counts and dead space
      --list-codecs         list the codecs and their parameters

Archive and paths:
  -f, --file ARCHIVE        the archive (required); .ect is added to a name
                            with no extension
  -C, --directory DIR       change to DIR first
  -d, --destination DIR     extract into DIR, creating it if needed
  -T, --files-from FILE     read the paths from FILE (- for stdin)
      --exclude GLOB        leave out matching paths (repeatable)
  -X, --exclude-from FILE   read exclude globs from FILE, one on each line
  -R, --regex RE            keep only paths that RE matches in full
      --exclude-regex RE    leave out paths that RE matches in full
  -h, --dereference         store what a symbolic link points to
      --one-file-system     do not enter other filesystems
      --no-dedup            store each copy of the same content in full

Compression:
  -Z, --compress SPEC       NAME[:key[=value],...] or none; the default is
                            zstd at level 12 (zstd:level=3 is faster);
                            zstd:train adds a dictionary of the best size:
                            smaller archives of many small, similar files,
                            but slower to create
  -z, --gzip                the same as --compress gzip
  -J, --xz                  the same as --compress xz
      --zstd                the same as --compress zstd
      --chunk-size SIZE     compress in chunks of SIZE (default 4MiB)

Encryption:
  -e, --encrypt             encrypt a new archive (asks for a passphrase)
      --encrypt-index       also encrypt the index: names, sizes, times
      --passphrase-file F   read the passphrase from the first line of F
      --passphrase-env VAR  read the passphrase from the variable VAR
      --new-passphrase-file F, --new-passphrase-env VAR
                            the new passphrase, for --change-passphrase
      --kdf-time N, --kdf-memory KIB, --kdf-threads N
                            the Argon2id cost, for -c and --change-passphrase

Changes:
      --on-conflict MODE    with -r: replace (default), skip or error
      --update-mode MODE    with -u: newer (default), different or digest
      --recompress SPEC     with --compact: encode every member again
      --quick               with --verify: check the structure only

Extraction:
  -k, --keep-existing       never replace an existing file
      --overwrite           replace existing files (the default)
      --newer-only          replace only when the member is newer
  -O, --to-stdout           write the content to standard output
  -p, --preserve-permissions  modes exactly, with setuid and no umask; ACLs,
                            and privileged xattrs as root (trusted archives)
      --preserve-owner      restore the owner (root only)
      --preserve-devices    create device nodes (root only)
      --no-xattrs, --no-acls, --no-owner
                            do not record, or do not restore, this metadata

Output and work:
  -v, --verbose             list members as they are processed
  -n, --dry-run             with -c, -r, -u, -x or --delete: show the paths
                            the operation would write or delete, and change
                            nothing
  -q, --quiet               errors only
      --long                with -t: the same as -v
      --json                with -t: a listing for programs
      --progress            a progress line on a terminal
  -j, --workers N           the number of workers (default: 3/4 of the CPUs)
      --memory-limit SIZE   the memory for data in flight
      --spill-threshold SIZE  move a member to disk above SIZE (default 32MiB)
      --keep-going          go on after an error on one member (exit 1)

Configuration:
      --config FILE         read the configuration from FILE
      --no-config           read no configuration file and no EICTAR_* variable
      --show-config         show each setting and where it came from, and exit
      --help                print this help
      --version             print the version

Settings can also come from ~/.eictarrc and EICTAR_* variables; see
--show-config. The archive is one seekable file: it cannot be read from or
written to a pipe. Full documentation: man ./doc/eictar.1.
`

func writeUsage(w io.Writer) { fmt.Fprint(w, usageText) }

// EffectiveSettings renders --show-config: every setting that a
// configuration can give, its value in effect, and where the value came from
// (doc/design.md 11).
func EffectiveSettings(o *Options) string {
	var b strings.Builder
	file := o.configFile
	switch {
	case o.NoConfig:
		file = "none (--no-config: no file and no EICTAR_* variables)"
	case file == "":
		file = "none found"
	}
	fmt.Fprintf(&b, "# configuration file: %s\n", file)
	if o.Op != OpNone {
		fmt.Fprintf(&b, "# operation: %v\n", o.Op)
	}

	keys := make([]string, 0, len(configKeys))
	for k := range configKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows [][]string
	for _, key := range keys {
		value := ""
		if key == "compress" {
			value = o.Compress.String()
		} else if f := o.flags.Lookup(key); f != nil {
			value = f.Value.String()
		}
		rows = append(rows, []string{key, "=", value, "(" + o.sourceOf(key) + ")"})
	}
	codecs := make([]string, 0, len(o.codecDefaults))
	for name := range o.codecDefaults {
		codecs = append(codecs, name)
	}
	sort.Strings(codecs)
	for _, name := range codecs {
		params := make([]string, 0, len(o.codecDefaults[name]))
		for p := range o.codecDefaults[name] {
			params = append(params, p)
		}
		sort.Strings(params)
		for _, p := range params {
			key := "codec." + name + "." + p
			rows = append(rows, []string{key, "=", o.codecDefaults[name][p], "(" + o.sources[key] + ")"})
		}
	}
	writeTable(&b, rows, nil)
	return b.String()
}

// sourceOf says where the value of a setting came from.
func (o *Options) sourceOf(key string) string {
	switch src, fromConfig := o.sources[key]; {
	case fromConfig:
		return src
	case o.explicit[key]:
		return "command line"
	case key == "compress" && (o.explicit["gzip"] || o.explicit["xz"] || o.explicit["zstd"]):
		return "command line"
	}
	if o.Op != OpNone && !appliesTo(key, o.Op) {
		return "default; not used by this operation"
	}
	return "default"
}
