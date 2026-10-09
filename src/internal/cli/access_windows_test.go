//go:build windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	testYou   = "S-1-5-21-1-2-3-1001"
	testOther = "S-1-5-21-1-2-3-1002"
	users     = "S-1-5-32-545"
	everyone  = "S-1-1-0"
)

// TestExposure: the owner and the ACEs that the check reports, for read and
// for write. Each descriptor is SDDL; FA, FR and FW are the file rights for
// all, read and write.
func TestExposure(t *testing.T) {
	you, err := windows.StringToSid(testYou)
	if err != nil {
		t.Fatal(err)
	}
	private := "(A;;FA;;;" + testYou + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, tc := range []struct {
		name    string
		sddl    string
		owner   string
		readers []string
		writers []string
	}{
		{"private", "O:" + testYou + "D:P" + private, "", nil, nil},
		{"owned by SYSTEM", "O:SYD:P" + private, "", nil, nil},
		{"owned by Administrators", "O:BAD:P" + private, "", nil, nil},
		{"owned by another account", "O:" + testOther + "D:P" + private, testOther, nil, nil},
		{"Users can read", "O:" + testYou + "D:P" + private + "(A;;FR;;;BU)", "", []string{users}, nil},
		{"Users can write", "O:" + testYou + "D:P" + private + "(A;;FW;;;BU)", "", nil, []string{users}},
		{"another account has all", "O:" + testYou + "D:P(A;;FA;;;" + testOther + ")", "", []string{testOther}, []string{testOther}},
		{"Everyone has GENERIC_ALL", "O:" + testYou + "D:P(A;;GA;;;WD)", "", []string{everyone}, []string{everyone}},
		{"Users can change the ACL", "O:" + testYou + "D:P(A;;WD;;;BU)", "", []string{users}, []string{users}},
		{"inherit-only", "O:" + testYou + "D:P" + private + "(A;OICIIO;FA;;;BU)", "", nil, nil},
		{"deny before allow", "O:" + testYou + "D:P(D;;FW;;;BU)(A;;FRFW;;;BU)", "", []string{users}, nil},
		{"deny after allow", "O:" + testYou + "D:P(A;;FRFW;;;BU)(D;;FW;;;BU)", "", []string{users}, []string{users}},
		{"deny to Everyone", "O:" + testYou + "D:P(D;;FW;;;WD)(A;;FRFW;;;BU)", "", []string{users}, nil},
		{"NULL DACL", "O:" + testYou + "D:NO_ACCESS_CONTROL", "", []string{everyone}, []string{everyone}},
		{"empty DACL", "O:" + testYou + "D:P", "", nil, nil},
		{"two accounts once each", "O:" + testYou + "D:P(A;;FR;;;BU)(A;;FA;;;BU)(A;;FR;;;WD)", "", []string{users, everyone}, []string{users}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				what string
				mask windows.ACCESS_MASK
				want []string
			}{{"readers", readRights, tc.readers}, {"writers", writeRights, tc.writers}} {
				owner, others, err := exposure(sd, you, c.mask)
				if err != nil {
					t.Fatal(err)
				}
				if got := sidString(owner); got != tc.owner {
					t.Errorf("owner %q, want %q", got, tc.owner)
				}
				var got []string
				for _, s := range others {
					got = append(got, s.String())
				}
				if !slices.Equal(got, c.want) {
					t.Errorf("%s %q, want %q", c.what, got, c.want)
				}
			}
		})
	}
}

func sidString(s *windows.SID) string {
	if s == nil {
		return ""
	}
	return s.String()
}

// setACL gives path a protected DACL: all rights to you, and extra ACEs.
func setACL(t *testing.T, path, extra string) {
	t.Helper()
	you, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FA;;;%s)%s", you, extra))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		t.Fatal(err)
	}
}

// TestConfigFileACL: a configuration file that Users can write is refused.
// One that Users can only read is used, as on Unix.
func TestConfigFileACL(t *testing.T) {
	for _, tc := range []struct {
		extra  string
		refuse bool
	}{{"", false}, {"(A;;FR;;;BU)", false}, {"(A;;FW;;;BU)", true}, {"(A;;FA;;;WD)", true}} {
		home := t.TempDir()
		p := writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 2\n")
		setACL(t, p, tc.extra)
		withEnv(t, home)
		err := parseErr(t, "-cf", "a", "p")
		if refused := err != nil && strings.Contains(err.Error(), "can write it"); refused != tc.refuse || !tc.refuse && err != nil {
			t.Errorf("ACL %q: %v, want a refusal: %v", tc.extra, err, tc.refuse)
		}
	}
}

// TestPassphraseFileACL: a warning for a passphrase file that Users can read
// (doc/Security_Audit.md, finding 8).
func TestPassphraseFileACL(t *testing.T) {
	for _, tc := range []struct {
		extra string
		warn  bool
	}{{"", false}, {"(A;;FA;;;SY)(A;;FA;;;BA)", false}, {"(A;;FR;;;BU)", true}, {"(A;;FW;;;BU)", false}} {
		p := filepath.Join(t.TempDir(), "pass")
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		setACL(t, p, tc.extra)
		var warned []string
		passphraseSource{file: p}.warnIfInsecureSource(func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) })
		if got := len(warned) == 1 && strings.Contains(warned[0], `BUILTIN\Users`); got != tc.warn {
			t.Errorf("ACL %q: warnings %q, want a warning: %v", tc.extra, warned, tc.warn)
		}
	}
}
