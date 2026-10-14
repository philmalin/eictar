package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const goldenDir = "../../src/internal/archive/testdata/golden"

func TestRun(t *testing.T) {
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("golden\nsecond line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(dir, "wrong")
	if err := os.WriteFile(wrong, []byte("Golden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notArchive := filepath.Join(dir, "x.ect")
	if err := os.WriteFile(notArchive, make([]byte, 200), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(goldenDir, "plain.ect")
	enc := filepath.Join(goldenDir, "encrypted.ect")
	for _, tc := range []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"-t", plain}, 0, `"path":"g/keep.txt","type":"hardlink"`},
		{[]string{"-p", pass, "-t", enc}, 0, `"hardlink":"g/hard.txt"`},
		{[]string{"-p", pass, "-c", enc}, 0, ""},
		{[]string{"-c", filepath.Join(goldenDir, "shared.ect")}, 0, ""},
		{[]string{"-p", wrong, "-t", enc}, 1, "passphrase is wrong"},
		{[]string{"-t", enc}, 3, "no passphrase"},
		{[]string{"-p", pass, "-t", plain}, 1, "not encrypted"},
		{[]string{"-t", notArchive}, 1, "magic"},
		{[]string{"-t", filepath.Join(dir, "none.ect")}, 3, "none"},
		{[]string{"-p", filepath.Join(dir, "none"), "-t", enc}, 3, "none"},
		{[]string{"-t", "-c", plain}, 2, "one of"},
		{[]string{"-t"}, 2, "one of"},
		{[]string{"-q", plain}, 2, "not defined"},
		{[]string{"-x", filepath.Join(dir, "out"), plain}, 0, ""},
		{[]string{"-x", filepath.Join(dir, "out"), plain}, 3, "exists"},
	} {
		if runtime.GOOS == "windows" && tc.args[0] == "-x" {
			continue // the golden archive has a symbolic link
		}
		var stdout, stderr bytes.Buffer
		code := run(tc.args, &stdout, &stderr)
		if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.out) {
			t.Errorf("%v: exit %d, want %d, with %q\nstdout: %s\nstderr: %s", tc.args, code, tc.code, tc.out, stdout.String(), stderr.String())
		}
	}
	var stdout bytes.Buffer
	run([]string{"-t", plain}, &stdout, &bytes.Buffer{})
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 8 {
		t.Fatalf("%d lines, want 8", len(lines))
	}
	for _, l := range lines {
		var e entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.Type == "reg" && len(e.SHA256) != 64 {
			t.Errorf("%s: sha256 %q", e.Path, e.SHA256)
		}
	}
	if b64IfNotUTF8("\xff") != "/w==" || b64IfNotUTF8("é") != "" {
		t.Error("b64IfNotUTF8")
	}
}
