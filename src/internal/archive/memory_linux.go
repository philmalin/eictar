//go:build linux

package archive

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// totalMemory returns the machine's RAM in bytes, or 0 when it cannot be
// determined. The budget falls back to a worker-count-based figure then.
func totalMemory() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kib * 1024
	}
	return 0
}
