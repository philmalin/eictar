package archive

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"eictar/src/internal/format"
	"eictar/src/internal/meta"
	"eictar/src/internal/testutil"
)

// TestXattrsFromAnotherPlatform is open question 5, as decided for M8
// (doc/design.md 7.7): names are recorded exactly, each name is applied where
// the destination takes it, and the rest are listed in one notice.
//
// The member carries a Linux name and a macOS name. macOS takes both. Linux,
// FreeBSD and NetBSD take user.ok and refuse com.apple.quarantine. OpenBSD
// has no extended attributes and refuses both.
func TestXattrsFromAnotherPlatform(t *testing.T) {
	// Where the platform has xattrs, the filesystem must have them too, or
	// every name is refused and the test means nothing: Xattr skips then.
	// Where the platform has none (OpenBSD), the test runs: both names must
	// be refused and listed.
	if meta.Supports.Xattrs {
		probe := testutil.NewTree(t)
		probe.Text("p", 0o644, "p").Xattr("p", "user.probe", []byte("x"))
	}

	archive, err := craftArchive(t, "none", []byte("content"), func(m *format.Member) {
		m.Xattrs = map[string][]byte{
			"user.ok":              []byte("linux"),
			"com.apple.quarantine": []byte("0081;00000000;Safari;"),
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	rep := &recordingReporter{}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Reporter: rep}); err != nil {
		t.Fatalf("extract: %v", err)
	}

	var refused []string
	switch {
	case !meta.Supports.Xattrs:
		refused = []string{"com.apple.quarantine", "user.ok"}
	case runtime.GOOS == "darwin":
		refused = nil
	default:
		refused = []string{"com.apple.quarantine"}
	}
	notices := strings.Join(rep.warnings, "\n")
	for _, name := range []string{"com.apple.quarantine", "user.ok"} {
		want := false
		for _, r := range refused {
			want = want || r == name
		}
		if got := strings.Contains(notices, name); got != want {
			t.Errorf("%s: in the notice = %v, want %v\nnotices: %q", name, got, want, rep.warnings)
		}
	}
	if len(refused) > 0 && len(rep.warnings) != 1 {
		t.Errorf("want one notice for the refused names, got %q", rep.warnings)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "member.bin")); err != nil || string(got) != "content" {
		t.Errorf("the file itself: %q, %v", got, err)
	}
}

// TestPipeExtraction: a pipe is created where the platform has mkfifoat, and
// skipped with a notice where it has not (macOS). A path-based mkfifo could
// be redirected by a planted link (doc/design.md 7.6).
func TestPipeExtraction(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("f.txt", 0o644, "x").Fifo("pipe", 0o640)
	archive := filepath.Join(t.TempDir(), "p.eictar")
	if _, err := CreateArchive(CreateConfig{Archive: archive, Paths: []string{"f.txt", "pipe"}, BaseDir: tree.Root}); err != nil {
		t.Fatal(err)
	}
	rep := &recordingReporter{}
	dest := t.TempDir()
	stats, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Reporter: rep})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	fi, statErr := os.Lstat(filepath.Join(dest, "pipe"))
	if meta.Supports.Fifos {
		if statErr != nil || fi.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("the pipe was not created: %v", statErr)
		}
		return
	}
	if statErr == nil || stats.Skipped != 1 || len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "cannot be created safely") {
		t.Errorf("on %s the pipe must be skipped with a notice: skipped=%d notices=%q", runtime.GOOS, stats.Skipped, rep.warnings)
	}
}
