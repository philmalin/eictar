//go:build aix || linux || solaris

package cli

import "golang.org/x/sys/unix"

// The requests that read and set the termios of a terminal.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
