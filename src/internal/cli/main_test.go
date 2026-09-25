package cli

import (
	"errors"
	"os"
	"testing"
)

// TestMain runs the package's tests with no configuration: no EICTAR_*
// variables and no home directory, whatever the developer's shell holds. A
// test that needs a configuration sets one up itself (see withEnv).
func TestMain(m *testing.M) {
	environ = func() []string { return nil }
	userHome = func() (string, error) { return "", errors.New("no home directory in tests") }
	os.Exit(m.Run())
}

// withEnv gives one test an environment and a home directory.
func withEnv(t *testing.T, home string, vars ...string) {
	t.Helper()
	oldEnv, oldHome := environ, userHome
	environ = func() []string { return vars }
	userHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { environ, userHome = oldEnv, oldHome })
}
