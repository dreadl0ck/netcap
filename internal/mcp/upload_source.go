package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxCaptureUpload = int64(10 << 30)

func openCaptureUpload(path string, limit int64) (*os.File, int64, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pcap" && ext != ".pcapng" {
		return nil, 0, fmt.Errorf("expected a .pcap or .pcapng regular file")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, 0, fmt.Errorf("capture must be a nonempty regular file of at most %d bytes", limit)
	}
	f, err := openCaptureNonblocking(path)
	if err != nil {
		return nil, 0, err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > limit {
		f.Close()
		return nil, 0, fmt.Errorf("opened capture is not a nonempty bounded regular file")
	}
	return f, opened.Size(), nil
}
