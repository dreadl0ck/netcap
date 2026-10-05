//go:build !windows

package behavior

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockBaseline(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("baseline is already in use or cannot be locked: %w", err)
	}
	return nil
}
