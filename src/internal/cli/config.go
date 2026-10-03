package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/pflag"

	"github.com/philmalin/eictar/src/internal/codec"
)

// The configuration layer (doc/design.md 11): settings from a configuration
// file and from EICTAR_* environment variables, below the command line in
// precedence and above the built-in defaults.

// environ and userHome are variables so that tests can run with a clean
// environment, whatever the developer's own shell holds.
var (
	environ  = os.Environ
	userHome = os.UserHomeDir
)

// allOps marks a key that applies to every operation.
var allOps []Operation

// adding are the operations that walk the filesystem into an archive.
var adding = []Operation{OpCreate, OpAppend, OpUpdate}

// walking are the operations that walk the filesystem: adding, and --diff,
// which must walk it as create did.
var walking = append([]Operation{OpDiff}, adding...)

// configKeys are the options a configuration can set, and the operations
// each one applies to. On any other operation a value from the configuration
// is ignored: compress = xz must not stop a listing, and preserve-owner in a
// file must not make every -t of a normal user fail for want of root.
//
// A key typed on the command line gets the command line's rules instead,
// which refuse an option where it means nothing.
var configKeys = map[string][]Operation{
	"compress":        append([]Operation{}, adding...),
	"workers":         allOps,
	"chunk-size":      allOps,
	"memory-limit":    allOps,
	"spill-threshold": allOps,

	"encrypt":       {OpCreate},
	"encrypt-index": {OpCreate},
	"kdf-time":      {OpCreate},
	"kdf-memory":    {OpCreate},
	"kdf-threads":   {OpCreate},

	"exclude":         append([]Operation{OpList, OpExtract}, walking...),
	"exclude-from":    append([]Operation{OpList, OpExtract}, walking...),
	"exclude-regex":   append([]Operation{OpList, OpExtract}, walking...),
	"dereference":     walking,
	"one-file-system": walking,
	"no-dedup":        adding,

	"preserve-permissions": {OpExtract},
	"preserve-owner":       {OpExtract},
	"preserve-devices":     {OpExtract},
	"no-xattrs":            append([]Operation{OpExtract}, walking...),
	"no-acls":              append([]Operation{OpExtract}, walking...),
	"no-owner":             append([]Operation{OpExtract}, walking...),

	"keep-existing": {OpExtract},
	"overwrite":     {OpExtract},
	"newer-only":    {OpExtract},

	"update-mode": {OpUpdate},
	"on-conflict": {OpAppend},
	"keep-going":  allOps,
	"long":        {OpList},
	"json":        {OpList},
	"quick":       {OpVerify},

	"verbose":  allOps,
	"quiet":    allOps,
	"progress": allOps,
}

// refusedKeys are options that exist but that a configuration must not set,
// with the reason (doc/design.md 11.1 and 11.4).
var refusedKeys = map[string]string{
	"passphrase":          "a passphrase never comes from the environment or a configuration file; use --passphrase-file or --passphrase-env on the command line",
	"passphrase-file":     "a passphrase source is given on the command line only",
	"passphrase-env":      "a passphrase source is given on the command line only",
	"new-passphrase-file": "a passphrase source is given on the command line only",
	"new-passphrase-env":  "a passphrase source is given on the command line only",
	"file":                "the archive is named on the command line only",
	"directory":           "-C is given on the command line only",
	"destination":         "-d is given on the command line only",
	"files-from":          "the paths are given on the command line only",
	"to-stdout":           "where extracted content goes is given on the command line only",
	"recompress":          "--recompress is part of the operation, given on the command line only",
	"regex":               "-R selects what the operation works on, given on the command line only",
	"config":              "a configuration cannot name another one",
	"no-config":           "--no-config is given on the command line only",
	"show-config":         "--show-config is given on the command line only",
}

// keyGroups are keys that decide one thing together. If the command line
// sets any key of a group, the configuration's values for the whole group are
// ignored: -z on the command line must win over compress = xz in a file, not
// be refused as a second codec.
var keyGroups = [][]string{
	{"compress", "gzip", "xz", "zstd"},
	{"keep-existing", "overwrite", "newer-only"},
	{"verbose", "quiet"},
}

// setting is one value from the configuration file or the environment.
type setting struct {
	key, value string
	source     string // "~/.eictarrc:3", or "EICTAR_WORKERS"
}

// layers is what the configuration file and the environment supply.
type layers struct {
	file     string               // the configuration file read, or ""
	settings map[string][]setting // by key; a list key can have several
	codecs   map[string]map[string]setting
}

// loadLayers reads the configuration file and the environment. The
// environment wins over the file, key by key. passphraseEnv is the variable
// that --passphrase-env names, and the one that --new-passphrase-env names:
// each holds a secret, not a setting, and may well be called EICTAR_ something.
func loadLayers(configFlag string, passphraseEnvs ...string) (*layers, error) {
	l := &layers{settings: map[string][]setting{}, codecs: map[string]map[string]setting{}}

	path, err := configPath(configFlag)
	if err != nil {
		return nil, err
	}
	if path != "" {
		l.file = path
		if err := l.readFile(path); err != nil {
			return nil, err
		}
	}
	if err := l.readEnv(passphraseEnvs); err != nil {
		return nil, err
	}
	return l, nil
}

// configPath chooses the one configuration file to read (doc/design.md 11):
// --config, then $EICTAR_CONFIG, then the XDG location, then ~/.eictarrc.
// A file that was named must exist; a default location may not.
func configPath(configFlag string) (string, error) {
	if configFlag != "" {
		return configFlag, nil
	}
	if p, ok := lookupEnv("EICTAR_CONFIG"); ok && p != "" {
		return p, nil
	}
	var candidates []string
	if x, ok := lookupEnv("XDG_CONFIG_HOME"); ok && x != "" {
		candidates = append(candidates, filepath.Join(x, "eictar", "config"))
	}
	if home, err := userHome(); err == nil && home != "" {
		if x, ok := lookupEnv("XDG_CONFIG_HOME"); !ok || x == "" {
			candidates = append(candidates, filepath.Join(home, ".config", "eictar", "config"))
		}
		candidates = append(candidates, filepath.Join(home, ".eictarrc"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", nil
}

func lookupEnv(name string) (string, bool) {
	for _, kv := range environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v, true
		}
	}
	return "", false
}

// readFile parses the configuration file (doc/design.md 11.3): key = value
// lines, # comments, and [codec.NAME] sections.
func (l *layers) readFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return &UsageError{fmt.Errorf("configuration file: %w", err)}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("configuration file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return &UsageError{fmt.Errorf("configuration file %s is not a regular file", path)}
	}
	// A person who can write the file can set exclude, and make a backup
	// smaller without a message (doc/design.md 11.4).
	if err := checkConfigOwner(fi); err != nil {
		return &UsageError{fmt.Errorf("configuration file %s: %w", path, err)}
	}

	section := ""
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := stripComment(sc.Text())
		if line == "" {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, n)
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return &UsageError{fmt.Errorf("%s: %q is not a [section]", where, line)}
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			name, ok := strings.CutPrefix(section, "codec.")
			if !ok {
				return &UsageError{fmt.Errorf("%s: unknown section [%s]; only [codec.NAME] exists", where, section)}
			}
			if _, err := codec.Lookup(name); err != nil {
				return &UsageError{fmt.Errorf("%s: [%s]: %w", where, section, err)}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return &UsageError{fmt.Errorf("%s: %q is not key = value", where, line)}
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if section != "" {
			if err := l.addCodec(strings.TrimPrefix(section, "codec."), key, value, where); err != nil {
				return err
			}
			continue
		}
		if err := l.add(key, value, where, true); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}

// stripComment removes a # comment and the spaces around what is left. A #
// starts a comment at the start of a line or after a space, so that a value
// can hold one: exclude = build#1 keeps its #.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			line = line[:i]
			break
		}
	}
	return strings.TrimSpace(line)
}

// readEnv reads the EICTAR_* variables (doc/design.md 11.2). A variable the
// program does not know is an error, not something to ignore: a misspelled
// EICTAR_COMPESS would otherwise give an archive at a level nobody chose.
func (l *layers) readEnv(passphraseEnvs []string) error {
	fromEnv := map[string][]setting{}
	for _, kv := range environ() {
		name, value, _ := strings.Cut(kv, "=")
		rest, ok := strings.CutPrefix(name, "EICTAR_")
		if !ok || name == "EICTAR_CONFIG" || slices.Contains(passphraseEnvs, name) {
			continue
		}
		if c, ok := strings.CutPrefix(rest, "CODEC_"); ok {
			codecName, param, ok := strings.Cut(c, "_")
			if !ok {
				return &UsageError{fmt.Errorf("%s: want EICTAR_CODEC_<NAME>_<PARAM>", name)}
			}
			if err := l.addCodec(strings.ToLower(codecName), strings.ToLower(param), value, name); err != nil {
				return err
			}
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(rest, "_", "-"))
		if err := checkKey(key, name); err != nil {
			return err
		}
		fromEnv[key] = append(fromEnv[key], setting{key, value, name})
	}
	// The environment replaces what the file says, key by key.
	for key, s := range fromEnv {
		l.settings[key] = s
	}
	return nil
}

// checkKey refuses a key that a configuration cannot set.
func checkKey(key, where string) error {
	if why, refused := refusedKeys[key]; refused {
		return &UsageError{fmt.Errorf("%s: %s", where, why)}
	}
	if _, ok := configKeys[key]; !ok {
		return &UsageError{fmt.Errorf("%s: unknown setting %q", where, key)}
	}
	return nil
}

func (l *layers) add(key, value, where string, fromFile bool) error {
	if err := checkKey(key, where); err != nil {
		return err
	}
	if key == "exclude" || key == "exclude-regex" {
		l.settings[key] = append(l.settings[key], setting{key, value, where})
		return nil
	}
	if fromFile && len(l.settings[key]) > 0 {
		return &UsageError{fmt.Errorf("%s: %s is set twice (first at %s)", where, key, l.settings[key][0].source)}
	}
	l.settings[key] = []setting{{key, value, where}}
	return nil
}

// addCodec records a default for one codec parameter, and checks it now, so
// that a bad value names the line or the variable it came from.
func (l *layers) addCodec(name, param, value, where string) error {
	if _, err := codec.Lookup(name); err != nil {
		return &UsageError{fmt.Errorf("%s: %w", where, err)}
	}
	enc, err := codec.NewEncoder(name, codec.Params{param: value}, 1)
	if err != nil {
		return &UsageError{fmt.Errorf("%s: %w", where, err)}
	}
	enc.Close()
	if l.codecs[name] == nil {
		l.codecs[name] = map[string]setting{}
	}
	l.codecs[name][param] = setting{param, value, where}
	return nil
}

// apply sets each configured option that the command line did not set, and
// that applies to this operation. It records where each value came from, for
// --show-config.
func (l *layers) apply(o *Options, fs *pflag.FlagSet) error {
	onCommandLine := map[string]bool{}
	for key := range configKeys {
		onCommandLine[key] = fs.Changed(key)
	}
	for _, group := range keyGroups {
		set := false
		for _, k := range group {
			set = set || fs.Changed(k)
		}
		for _, k := range group {
			onCommandLine[k] = onCommandLine[k] || set
		}
	}

	keys := make([]string, 0, len(l.settings))
	for k := range l.settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if onCommandLine[key] || !appliesTo(key, o.Op) {
			continue
		}
		for _, s := range l.settings[key] {
			value := s.value
			if isBoolFlag(fs, key) {
				v, err := parseBool(value)
				if err != nil {
					return &UsageError{fmt.Errorf("%s: %s: %w", s.source, key, err)}
				}
				value = v
			}
			if err := fs.Set(key, value); err != nil {
				return &UsageError{fmt.Errorf("%s: %s: %w", s.source, key, err)}
			}
		}
		o.sources[key] = l.settings[key][0].source
	}

	for name, params := range l.codecs {
		for param, s := range params {
			if o.codecDefaults[name] == nil {
				o.codecDefaults[name] = map[string]string{}
			}
			o.codecDefaults[name][param] = s.value
			o.sources["codec."+name+"."+param] = s.source
		}
	}
	o.configFile = l.file
	return nil
}

// appliesTo reports whether a configured key means anything for op. With no
// operation - --show-config on its own - everything is shown.
func appliesTo(key string, op Operation) bool {
	ops := configKeys[key]
	if ops == nil || op == OpNone {
		return true
	}
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}

func isBoolFlag(fs *pflag.FlagSet, key string) bool {
	f := fs.Lookup(key)
	return f != nil && f.Value.Type() == "bool"
}

// parseBool accepts the spellings people write in a file or a shell.
func parseBool(s string) (string, error) {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return "true", nil
	case "0", "false", "no", "off":
		return "false", nil
	}
	return "", errors.New("want true or false (1/0, yes/no, on/off)")
}

// withCodecDefaults fills in the parameters the spec leaves out from the
// configured defaults for its codec.
func (o *Options) withCodecDefaults(spec CompressSpec) CompressSpec {
	defaults := o.codecDefaults[spec.Name]
	if len(defaults) == 0 {
		return spec
	}
	params := make(map[string]string, len(defaults)+len(spec.Params))
	for k, v := range defaults {
		params[k] = v
	}
	for k, v := range spec.Params {
		params[k] = v
	}
	spec.Params = params
	return spec
}
