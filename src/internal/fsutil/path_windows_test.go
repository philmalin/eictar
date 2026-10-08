package fsutil

import "testing"

// TestStorePathRemovesTheVolume: an absolute path on Windows starts with a
// drive or a UNC share. StorePath removed only a leading separator, so
// C:\Users\a.txt was stored as C:/Users/a.txt, with no notice, and the
// extraction refused it as an escape.
func TestStorePathRemovesTheVolume(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\a.txt`:               "Users/a.txt",
		`C:/Users/a.txt`:               "Users/a.txt",
		`c:a.txt`:                      "a.txt", // relative to the current directory of drive C
		`C:\`:                          RootPath,
		`\\server\share\dir\a.txt`:     "dir/a.txt",
		`\\?\C:\Users\a.txt`:           "Users/a.txt",
		`\Users\a.txt`:                 "Users/a.txt",
		`C:\Users\..\..\Windows\a.txt`: "Windows/a.txt",
	} {
		got, stripped, err := StorePath(in)
		if err != nil || got != want || !stripped {
			t.Errorf("StorePath(%q) = %q, %v, %v; want %q, true, nil", in, got, stripped, err, want)
		}
	}
}
