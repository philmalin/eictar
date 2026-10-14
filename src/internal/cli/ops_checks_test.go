package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
)

// Tests of ops.go that the other tests of the package and the operational
// tests do not reach: the refusals of each operation, the inputs of -T, and
// the parts of the listings.

// runCLI runs the command line, and returns the exit code and the output.
func runCLI(argv ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(argv, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// opsTree makes a directory with t/a.txt and t/b.txt, and an archive of t.
func opsTree(t *testing.T) (dir, archivePath string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "t"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"t/a.txt": "alpha", "t/b.txt": "bravo"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	archivePath = filepath.Join(dir, "a.ect")
	if code, _, stderr := runCLI("-cf", archivePath, "-C", dir, "t"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	return dir, archivePath
}

// TestOperationRefusals: each operation refuses an input that it cannot
// read, with the right exit code, before it does anything.
func TestOperationRefusals(t *testing.T) {
	dir, archivePath := opsTree(t)
	missing := filepath.Join(dir, "missing")
	file := filepath.Join(dir, "t", "a.txt")
	newArchive := filepath.Join(dir, "new.ect")
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		argv []string
		code int
		text string
	}{
		{"create, an empty -T", []string{"-cf", newArchive, "-C", dir, "-T", empty}, ExitUsage, "no paths to archive"},
		{"create, -C missing", []string{"-cf", newArchive, "-C", missing, "t"}, ExitIO, missing},
		{"create, -C a file", []string{"-cf", newArchive, "-C", file, "t"}, ExitIO, "not a directory"},
		{"create, two -C", []string{"-cf", newArchive, "-C", dir, "-C", dir, "t"}, ExitUsage, "more than one -C"},
		{"create, -T missing", []string{"-cf", newArchive, "-C", dir, "-T", missing}, ExitIO, "reading -T"},
		{"create, -X missing", []string{"-cf", newArchive, "-C", dir, "-X", missing, "t"}, ExitIO, "reading -X"},
		{"create, passphrase file missing", []string{"-cf", newArchive, "-C", dir, "-e", "--passphrase-file", missing, "t"}, -1, "reading the passphrase file"},
		{"list, -X missing", []string{"-tf", archivePath, "-X", missing}, ExitIO, "reading -X"},
		{"extract, -X missing", []string{"-xf", archivePath, "-d", t.TempDir(), "-X", missing}, ExitIO, "reading -X"},
		{"extract, two -C", []string{"-xf", archivePath, "-C", dir, "-C", dir}, ExitUsage, "more than one -C"},
		{"extract, -C missing", []string{"-xf", archivePath, "-C", missing}, ExitIO, missing},
		{"extract, -C a file", []string{"-xf", archivePath, "-C", file}, ExitIO, "not a directory"},
	} {
		code, _, stderr := runCLI(tc.argv...)
		if code == ExitOK || (tc.code >= 0 && code != tc.code) || !strings.Contains(stderr, printable(tc.text)) {
			t.Errorf("%s: exit %d, %q; want exit %d and %q", tc.name, code, stderr, tc.code, tc.text)
		}
	}
	if _, err := os.Stat(newArchive); err == nil {
		t.Error("a refused create left an archive")
	}
}

// TestExtractWithOneChdir: one -C is the destination, as -d is.
func TestExtractWithOneChdir(t *testing.T) {
	_, archivePath := opsTree(t)
	dest := t.TempDir()
	if code, _, stderr := runCLI("-xf", archivePath, "-C", dest); code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "t", "a.txt")); err != nil || string(b) != "alpha" {
		t.Errorf("%q, %v", b, err)
	}
}

// TestFilesFrom: -T takes one path on each line, with the blank lines and
// the carriage returns of a list from Windows left out, from a file or from
// the standard input.
func TestFilesFrom(t *testing.T) {
	dir, _ := opsTree(t)
	list := filepath.Join(dir, "list")
	if err := os.WriteFile(list, []byte("t/a.txt\r\n\r\n\nt/b.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	listed := func(archivePath string) string {
		code, stdout, stderr := runCLI("-tf", archivePath)
		if code != ExitOK {
			t.Fatalf("list: exit %d: %s", code, stderr)
		}
		return stdout
	}
	a := filepath.Join(dir, "from-file.ect")
	if code, _, stderr := runCLI("-cf", a, "-C", dir, "-T", list); code != ExitOK {
		t.Fatalf("create -T file: exit %d: %s", code, stderr)
	}
	if got := listed(a); got != "t/a.txt\nt/b.txt\n" {
		t.Errorf("-T file: %q", got)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = saved; r.Close() })
	w.WriteString("t/b.txt\n")
	w.Close()
	b := filepath.Join(dir, "from-stdin.ect")
	if code, _, stderr := runCLI("-cf", b, "-C", dir, "-T", "-"); code != ExitOK {
		t.Fatalf("create -T -: exit %d: %s", code, stderr)
	}
	if got := listed(b); got != "t/b.txt\n" {
		t.Errorf("-T -: %q", got)
	}
}

// TestListCodecsRanges: a parameter shows its choices, or its range, or
// neither when it has none.
func TestListCodecsRanges(t *testing.T) {
	code, stdout, stderr := runCLI("--list-codecs")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	line := func(codecName, param string) string {
		in := false
		for _, l := range strings.Split(stdout, "\n") {
			if !strings.HasPrefix(l, " ") {
				in = strings.HasPrefix(l, codecName+" ")
				continue
			}
			if in && strings.HasPrefix(strings.TrimSpace(l), param+" ") {
				return l
			}
		}
		t.Fatalf("no line for %s %s in %q", codecName, param, stdout)
		return ""
	}
	for _, tc := range []struct{ codecName, param, want, not string }{
		{"s2", "mode", "one of ", ".."},
		{"zstd", "level", "1..22", "one of"},
		{"xz", "preset", "0..9", "one of"},
		{"zstd", "train", "4096..1048576", "one of"},
	} {
		l := line(tc.codecName, tc.param)
		if !strings.Contains(l, tc.want) || strings.Contains(l, tc.not) {
			t.Errorf("%s %s: %q; want %q and not %q", tc.codecName, tc.param, l, tc.want, tc.not)
		}
	}
}

// TestOwnerColumn: the names where there are, the numbers where not, and
// "-" with no owner.
func TestOwnerColumn(t *testing.T) {
	id := func(v uint32) *uint32 { return &v }
	for _, tc := range []struct {
		m    format.Member
		want string
	}{
		{format.Member{UID: id(1), GID: id(2), Uname: "u", Gname: "g"}, "u/g"},
		{format.Member{UID: id(1), GID: id(2)}, "1/2"},
		{format.Member{UID: id(1)}, "-"},
		{format.Member{GID: id(2)}, "-"},
	} {
		if got := owner(&tc.m); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.m, got, tc.want)
		}
	}
}

// TestListingOfASharer: a member that shares the content of another stores
// nothing, and the totals of -vv count it.
func TestListingOfASharer(t *testing.T) {
	digest := bytes.Repeat([]byte{0xcd}, 32)
	sharer := format.Member{Path: "b", Type: format.TypeReg, Mode: 0o644, Size: 5, Data: 1, Digest: digest}
	cols := longColumns(nil, &sharer, true)
	if got := strings.Join(cols[3:9], " "); got != "- - - - - cdcdcdcdcdcdcdcd" {
		t.Errorf("sharer: %q", got)
	}
	owner := format.Member{Path: "a", Type: format.TypeReg, Size: 5, Length: 9}
	l := &archive.Listing{Members: []format.Member{owner}}
	if got := totalsLine(l); strings.Contains(got, "same as") {
		t.Errorf("no sharer: %q", got)
	}
	l.Members = append(l.Members, sharer)
	if got := totalsLine(l); !strings.Contains(got, ", 1 same as another (0 bytes not stored)") {
		t.Errorf("a sharer: %q", got)
	}
}

// TestJSONListFields: the fields that depend on the type and the blob.
func TestJSONListFields(t *testing.T) {
	l := &archive.Listing{Members: []format.Member{
		{Path: "f", Type: format.TypeReg, Codec: format.NoCodec, Length: 3, Size: 3, Chunks: []uint32{3},
			Enc: &format.EncInfo{}, Sparse: []format.SparseSegment{{Offset: 0, Length: 3}}},
		{Path: "g", Type: format.TypeReg, Codec: format.NoCodec},
		{Path: "h", Type: format.TypeHardlink, HardlinkTo: 7},
	}}
	var out bytes.Buffer
	if err := writeJSONList(&out, l); err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(out.Bytes(), &recs); err != nil {
		t.Fatal(err)
	}
	if recs[0]["sparse"] != true || recs[0]["encrypted"] != true {
		t.Errorf("f: %v", recs[0])
	}
	if _, ok := recs[1]["sparse"]; ok || recs[1]["encrypted"] != false {
		t.Errorf("g: %v", recs[1])
	}
	if recs[2]["hardlink_to"] != "member 7" {
		t.Errorf("h: %v", recs[2])
	}
	if _, ok := recs[0]["hardlink_to"]; ok {
		t.Errorf("f has a hardlink target: %v", recs[0])
	}
}

// TestListingOfSharersThroughRun: the long listing names the owner of the
// content of a member, and says when that owner is deleted, or is the
// earlier version of the member itself.
func TestListingOfSharersThroughRun(t *testing.T) {
	dir, archivePath := opsTree(t)
	if err := os.WriteFile(filepath.Join(dir, "t", "c.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI("-rf", archivePath, "-C", dir, "t/c.txt", "t/b.txt"); code != ExitOK {
		t.Fatalf("append: exit %d: %s", code, stderr)
	}
	if code, _, stderr := runCLI("--delete", "-f", archivePath, "t/a.txt"); code != ExitOK {
		t.Fatalf("delete: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runCLI("-tvf", archivePath)
	if code != ExitOK {
		t.Fatalf("list: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"t/c.txt same as deleted t/a.txt", "t/b.txt same as its earlier version"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("want %q in %q", want, stdout)
		}
	}
}

// TestLongListingOfADevice: the size column of a device is its numbers.
func TestLongListingOfADevice(t *testing.T) {
	fi, err := os.Lstat("/dev/null")
	if err != nil || fi.Mode()&fs.ModeCharDevice == 0 || runtime.GOOS == "windows" {
		t.Skip("no /dev/null")
	}
	// The numbers of /dev/null differ from one platform to the next.
	info := meta.Stat(fi)
	want := fmt.Sprintf(" %d,%d ", info.Major, info.Minor)
	archivePath := filepath.Join(t.TempDir(), "d.ect")
	if code, _, stderr := runCLI("-cf", archivePath, "-C", "/dev", "null"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runCLI("-tvf", archivePath)
	if code != ExitOK || !strings.Contains(stdout, want) {
		t.Errorf("exit %d, %q, %s; want %q", code, stdout, stderr, want)
	}
}

// TestDetailAlignsChunks: under -vv, the count of chunks lines up on the
// right, as the other numbers do.
func TestDetailAlignsChunks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big"), bytes.Repeat([]byte("x"), 12*512), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "small"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "a.ect")
	if code, _, stderr := runCLI("-cf", archivePath, "-C", dir, "--chunk-size", "512", "big", "small"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runCLI("-tvvf", archivePath)
	if code != ExitOK {
		t.Fatalf("list: exit %d: %s", code, stderr)
	}
	lines := strings.Split(stdout, "\n")
	if big := strings.Fields(lines[0]); big[6] != "12" {
		t.Errorf("chunks: %q", stdout)
	}
	// The column of the count of chunks ends where it ends for big.
	end := strings.Index(lines[0], " 12 ") + len(" 12")
	if lines[1][end-1] != '1' {
		t.Errorf("the count of chunks of small does not end under that of big:\n%s", stdout)
	}
}

// TestQuietReporter: -q leaves out the warnings.
func TestQuietReporter(t *testing.T) {
	var errOut bytes.Buffer
	(&reporter{errOut: &errOut, quiet: true}).Warn("a %s", "warning")
	if errOut.Len() != 0 {
		t.Errorf("quiet: %q", errOut.String())
	}
	(&reporter{errOut: &errOut}).Warn("a %s", "warning")
	if errOut.String() != "eictar: a warning\n" {
		t.Errorf("not quiet: %q", errOut.String())
	}
}

// TestLongVerboseExtract: -xv --long lists each member in the long form.
func TestLongVerboseExtract(t *testing.T) {
	_, archivePath := opsTree(t)
	code, stdout, stderr := runCLI("-xvf", archivePath, "--long", "-d", t.TempDir())
	if code != ExitOK || !strings.Contains(stdout, "-rw") || !strings.Contains(stdout, "t/a.txt") {
		t.Errorf("exit %d, %q, %s", code, stdout, stderr)
	}
}

// TestExtractPartial: a member that fails under --keep-going makes the exit
// code 1.
func TestExtractPartial(t *testing.T) {
	_, archivePath := opsTree(t)
	dest := t.TempDir()
	// t is a file where the archive has a directory.
	if err := os.WriteFile(filepath.Join(dest, "t"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI("-xf", archivePath, "-d", dest, "--keep-going")
	if code != ExitPartial {
		t.Errorf("exit %d, %s; want %d", code, stderr, ExitPartial)
	}
}
