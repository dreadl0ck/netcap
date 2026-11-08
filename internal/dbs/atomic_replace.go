//go:build !windows

package dbs

import "os"

func replaceAtomicFile(source, target string) error {
	return os.Rename(source, target)
}
