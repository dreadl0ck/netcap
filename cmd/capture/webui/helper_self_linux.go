//go:build linux && !appstore

package webui

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func runningImageMapped(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	file, err := os.Open("/proc/self/maps")
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 8<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		inode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil || inode != stat.Ino {
			continue
		}
		mapped, err := os.Stat(strings.Join(fields[5:], " "))
		if err == nil && os.SameFile(info, mapped) {
			return true
		}
	}
	return false
}
