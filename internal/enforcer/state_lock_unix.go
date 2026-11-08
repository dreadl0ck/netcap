//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package enforcer

import (
	"fmt"
	"os"
	"syscall"
)

func lockState(path string) (func() error, error) {
	f, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("state already locked: %w", err)
	}
	// Keep the inode in place: unlinking a flock file permits two owners to lock
	// different inodes at the same path. The OS releases the lock on process death.
	return f.Close, nil
}
