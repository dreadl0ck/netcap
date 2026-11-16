//go:build !unix

package mcp

import "os"

func openCaptureNonblocking(path string) (*os.File, error) { return os.Open(path) }
