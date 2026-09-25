//go:build openbsd

package meta

import (
	"fmt"
	"os"
)

// OpenBSD has no extended attributes: nothing is recorded, and nothing can
// be set (doc/design.md 15.1).

func ReadXattrs(string, bool) (map[string][]byte, error) { return nil, nil }

func SetXattr(_ *os.File, name string, _ []byte) error {
	return fmt.Errorf("setting %s: %w", name, ErrRefused)
}
