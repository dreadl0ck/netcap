//go:build darwin || linux

package collector

import (
	"io/fs"
	"syscall"
)

const recheckAllocationAvailable = true

func recheckAllocatedBytes(info fs.FileInfo) (int64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 {
		return 0, false
	}
	return stat.Blocks * 512, true
}
