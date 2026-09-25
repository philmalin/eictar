// Package cli parses the command line, the environment and the configuration
// file into the options the rest of the program acts on. It performs no
// archive work itself.
package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// CompressSpec is a parsed --compress argument: a codec name and the
// parameters selected for it (doc/design.md 10.2).
//
// Parameters are kept as strings here. The codec registry owns their meaning,
// their ranges and their defaults; the CLI's job is only to split them out.
type CompressSpec struct {
	Name   string
	Params map[string]string
}

// NoCompression is the spec meaning "store the content as it is".
const NoCompression = "none"

// IsNone reports whether the spec disables compression.
func (s CompressSpec) IsNone() bool { return s.Name == NoCompression }

// ParseCompressSpec parses "NAME[:k=v[,k=v]...]".
//
//	zstd
//	zstd:level=19
//	zstd:level=19,long=27
//	none
func ParseCompressSpec(s string) (CompressSpec, error) {
	if s == "" {
		return CompressSpec{}, fmt.Errorf("empty compression spec")
	}

	name, rest, hasParams := strings.Cut(s, ":")
	if name == "" {
		return CompressSpec{}, fmt.Errorf("compression spec %q has no codec name", s)
	}
	spec := CompressSpec{Name: name}
	if !hasParams {
		return spec, nil
	}
	if rest == "" {
		return CompressSpec{}, fmt.Errorf("compression spec %q ends with a colon but no parameters", s)
	}

	spec.Params = make(map[string]string)
	for _, kv := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return CompressSpec{}, fmt.Errorf("compression parameter %q is not k=v", kv)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			return CompressSpec{}, fmt.Errorf("compression spec %q has an empty parameter name", s)
		}
		if _, dup := spec.Params[k]; dup {
			// Silently keeping the last value would hand the user a
			// compression level they did not choose.
			return CompressSpec{}, fmt.Errorf("compression parameter %q given twice", k)
		}
		spec.Params[k] = v
	}
	return spec, nil
}

// String renders the spec back into its command-line form. Parameters are
// sorted so the output is stable, which matters for --show-config.
func (s CompressSpec) String() string {
	if len(s.Params) == 0 {
		return s.Name
	}
	keys := make([]string, 0, len(s.Params))
	for k := range s.Params {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var b strings.Builder
	b.WriteString(s.Name)
	for i, k := range keys {
		if i == 0 {
			b.WriteByte(':')
		} else {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(s.Params[k])
	}
	return b.String()
}

// Size is a byte count accepted in human form: 4MiB, 512K, 2g, 1048576.
type Size int64

// ParseSize parses a byte count with an optional unit suffix.
//
// Both the binary (KiB) and the short (K) forms mean 1024, because every tool
// a user reaches for alongside this one treats them that way, and a silent
// factor-of-1000 difference in a chunk size would be nasty to debug.
func ParseSize(s string) (Size, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	// Split the digits from the unit.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("size %q does not start with a number", orig)
	}
	digits, unit := s[:i], strings.TrimSpace(s[i:])

	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", orig, err)
	}

	var mult int64
	switch strings.ToLower(unit) {
	case "", "b":
		mult = 1
	case "k", "kib", "kb":
		mult = 1 << 10
	case "m", "mib", "mb":
		mult = 1 << 20
	case "g", "gib", "gb":
		mult = 1 << 30
	case "t", "tib", "tb":
		mult = 1 << 40
	default:
		return 0, fmt.Errorf("size %q has an unknown unit %q", orig, unit)
	}

	if n != 0 && mult != 1 && n > (1<<62)/mult {
		return 0, fmt.Errorf("size %q overflows", orig)
	}
	return Size(n * mult), nil
}

// String renders a size in the largest unit that divides it exactly, so a
// value read back from --show-config looks like what was typed.
func (s Size) String() string {
	n := int64(s)
	if n == 0 {
		return "0"
	}
	for _, u := range []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	} {
		if n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}
