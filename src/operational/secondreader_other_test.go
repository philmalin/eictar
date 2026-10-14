//go:build operational && !unix

package operational

import "testing"

// specialFiles adds nothing: this system has no named pipe, and a sparse
// file needs a call of its own.
func specialFiles(t *testing.T, dir string) {}
