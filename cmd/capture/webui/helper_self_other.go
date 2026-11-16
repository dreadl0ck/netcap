//go:build !linux && !appstore

package webui

import "os"

func runningImageMapped(path string) bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	current, err := os.Stat(executable)
	if err != nil {
		return false
	}
	candidate, err := os.Stat(path)
	return err == nil && candidate.Mode().IsRegular() && os.SameFile(current, candidate)
}
