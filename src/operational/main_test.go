//go:build operational

package operational

import (
	"os"
	"testing"

	"github.com/philmalin/eictar/src/internal/testutil"
)

// TestMain removes the binary that the tests built, after the tests.
func TestMain(m *testing.M) {
	code := m.Run()
	testutil.RemoveBinary()
	os.Exit(code)
}
