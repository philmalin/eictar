//go:build !unix

package ect

import (
	"os"
	"time"
)

// linkTimes does nothing: this system has no call that sets the times of a
// symbolic link through a directory.
func linkTimes(root *os.Root, p string, atime, mtime time.Time) error { return nil }
