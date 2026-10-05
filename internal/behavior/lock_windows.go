package behavior

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func lockBaseline(file *os.File) error {
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("baseline is already in use or cannot be locked: %w", err)
	}
	return nil
}
