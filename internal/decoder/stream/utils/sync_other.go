//go:build !darwin

package utils

import "os"

func syncFile(f *os.File) error { return f.Sync() }
