// Package runtimebudget leaves GC headroom inside Linux container memory limits.
package runtimebudget

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// Configure preserves explicit GOMEMLIMIT/runtime policy. The Go soft limit does
// not bound decoder-owned state or native allocations; the cgroup remains hard.
func Configure() {
	if runtime.GOOS != "linux" {
		return
	}
	_, explicit := os.LookupEnv("GOMEMLIMIT")
	if limit := automaticLimit(os.ReadFile, explicit, debug.SetMemoryLimit(-1)); limit > 0 {
		debug.SetMemoryLimit(limit)
	}
}

func automaticLimit(read func(string) ([]byte, error), explicit bool, current int64) int64 {
	if explicit || current != math.MaxInt64 {
		return 0
	}
	paths := []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}
	groups, _ := read("/proc/self/cgroup")
	for _, line := range strings.Split(string(groups), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || !strings.HasPrefix(fields[2], "/") {
			continue
		}
		root, name := "/sys/fs/cgroup", "memory.max"
		if fields[1] != "" {
			if !strings.Contains(","+fields[1]+",", ",memory,") {
				continue
			}
			root, name = root+"/memory", "memory.limit_in_bytes"
		}
		for path := filepath.Clean(fields[2]); ; path = filepath.Dir(path) {
			paths = append(paths, filepath.Join(root, path, name))
			if path == "/" {
				break
			}
		}
	}
	var hard int64
	for _, path := range paths {
		data, err := read(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		// v1 uses a near-MaxInt64 sentinel for unlimited; v2 spells it "max".
		if err == nil && value > 0 && value < 1<<60 && (hard == 0 || value < hard) {
			hard = value
		}
	}
	return hard / 4 * 3
}
