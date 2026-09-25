package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// TestManPageNamesEveryOption keeps doc/eictar.1 in step with the parser: a
// long option that the man page does not name is an option nobody can find.
func TestManPageNamesEveryOption(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "..", "doc", "eictar.1"))
	if err != nil {
		t.Fatal(err)
	}
	o := Defaults()
	fs, _ := o.flagSet("eictar")
	fs.VisitAll(func(f *pflag.Flag) {
		// In roff, a - that is meant as a hyphen-minus is written \-.
		want := `\-\-` + strings.ReplaceAll(f.Name, "-", `\-`)
		if !strings.Contains(string(page), want) {
			t.Errorf("doc/eictar.1 does not document --%s", f.Name)
		}
	})
}
