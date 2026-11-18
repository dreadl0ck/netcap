//go:build !darwin && !linux

package collector

import "io/fs"

const recheckAllocationAvailable = false

func recheckAllocatedBytes(fs.FileInfo) (int64, bool) { return 0, false }
