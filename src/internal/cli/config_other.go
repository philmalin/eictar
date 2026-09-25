//go:build !unix

package cli

import "os"

// checkConfigOwner has no owner and mode to check on this platform. Windows
// file permissions are ACLs, which this program does not read (§15.1).
func checkConfigOwner(os.FileInfo) error { return nil }
