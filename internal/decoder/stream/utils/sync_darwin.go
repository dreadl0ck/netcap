package utils

import (
	"os"

	"golang.org/x/sys/unix"
)

// syncFile flushes a per-stream output file to the device. os.File.Sync on darwin issues
// F_FULLFSYNC, which also drains the drive cache and costs tens of
// milliseconds; one per stream file made an 18,000-stream capture take 14
// minutes instead of seconds. fsync(2) still orders the data before the
// publishing rename for crash consistency.
func syncFile(f *os.File) error {
	for {
		err := unix.Fsync(int(f.Fd()))
		if err != unix.EINTR {
			return err
		}
	}
}
