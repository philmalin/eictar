//go:build !unix && !windows

package cli

import "os"

// checkConfigOwner has no owner and no permissions to check on this platform.
func checkConfigOwner(*os.File, os.FileInfo) error { return nil }

// passphraseFileExposure has no permissions to check on this platform.
func passphraseFileExposure(string) string { return "" }
