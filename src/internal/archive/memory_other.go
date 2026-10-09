//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package archive

// totalMemory is unavailable on this platform, so the budget is sized from the
// worker count alone. See budgetFor.
func totalMemory() int64 { return 0 }
