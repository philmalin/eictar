//go:build unix

package cli

import (
	"errors"
	"io"

	"golang.org/x/sys/unix"
)

// The calls that read and set the termios of a terminal. A test replaces
// them: a terminal that fails one call and not the other is hard to make.
var (
	getTermios = func(fd int) (*unix.Termios, error) { return unix.IoctlGetTermios(fd, ioctlReadTermios) }
	setTermios = func(fd int, t *unix.Termios) error { return unix.IoctlSetTermios(fd, ioctlWriteTermios, t) }
)

// readPassword reads one line from the terminal fd with echo off, as
// term.ReadPassword does. term.ReadPassword reads again after a read of 0
// bytes, and a terminal that has hung up gives 0 bytes to each read: the
// prompt then reads for ever, at the full speed of a CPU. Here the end of
// the input ends the line.
func readPassword(fd int) ([]byte, error) {
	old, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	s := *old
	s.Lflag &^= unix.ECHO
	s.Lflag |= unix.ICANON | unix.ISIG
	s.Iflag |= unix.ICRNL
	// With the echo on, the passphrase shows on the screen: stop.
	if err := setTermios(fd, &s); err != nil {
		return nil, err
	}
	defer setTermios(fd, old)
	return readPasswordLine(func(b []byte) (int, error) {
		for {
			n, err := unix.Read(fd, b)
			if !errors.Is(err, unix.EINTR) {
				return n, err
			}
		}
	})
}

// readPasswordLine reads a line, one byte at a time, so that it reads
// nothing after the line. It drops a '\r', and a '\b' removes the byte
// before it, as in term.ReadPassword. The end of the input ends the line,
// and with nothing read it is io.EOF.
func readPasswordLine(read func([]byte) (int, error)) ([]byte, error) {
	var b [1]byte
	var line []byte
	for {
		n, err := read(b[:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			if len(line) > 0 {
				return line, nil
			}
			return nil, io.EOF
		}
		switch b[0] {
		case '\n':
			return line, nil
		case '\r':
		case '\b':
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		default:
			line = append(line, b[0])
		}
	}
}
