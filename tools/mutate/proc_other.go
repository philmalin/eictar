//go:build !unix

package main

import "os/exec"

// ownGroup does nothing here: make mutate runs on the UNIX-like platforms.
func ownGroup(*exec.Cmd) {}

// killGroup does nothing here.
func killGroup(*exec.Cmd) {}
