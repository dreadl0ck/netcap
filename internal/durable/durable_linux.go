package durable

import (
	"os"

	"golang.org/x/sys/unix"
)

func barrier(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		err = unix.Syncfs(int(f.Fd()))
		if err != unix.EINTR {
			return err
		}
	}
}
