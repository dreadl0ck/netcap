//go:build !windows

package webtech

import (
	"os"
	"syscall"
)

func openCatalogue(root *os.Root) (*os.File, error) {
	return root.OpenFile(FileName, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
