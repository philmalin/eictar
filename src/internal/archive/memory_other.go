//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package archive

// totalMemory is unavailable outside Linux, so the budget is sized from the
// worker count alone. See budgetFor.
func totalMemory() int64 { return 0 }
