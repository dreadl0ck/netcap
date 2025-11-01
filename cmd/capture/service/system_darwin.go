//go:build darwin

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package service

import (
	"os/exec"
	"strconv"
	"strings"
)

// getTotalMemoryOS returns the total system memory in bytes for macOS
func getTotalMemoryOS() uint64 {
	return getTotalMemoryDarwin()
}

// getFreeMemoryOS returns the free system memory in bytes for macOS
func getFreeMemoryOS() uint64 {
	return getFreeMemoryDarwin()
}

// getTotalMemoryDarwin uses sysctl to get total memory on macOS
func getTotalMemoryDarwin() uint64 {
	cmd := exec.Command("sysctl", "-n", "hw.memsize")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	mem, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return 0
	}

	return mem
}

// getFreeMemoryDarwin uses vm_stat to get free memory on macOS
func getFreeMemoryDarwin() uint64 {
	cmd := exec.Command("vm_stat")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	var pageSize uint64 = 4096 // Default page size
	var freePages uint64
	var inactivePages uint64

	for _, line := range lines {
		if strings.HasPrefix(line, "page size of") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if size, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
					pageSize = size
				}
			}
		} else if strings.HasPrefix(line, "Pages free:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				// Remove trailing period
				numStr := strings.TrimSuffix(fields[2], ".")
				if pages, err := strconv.ParseUint(numStr, 10, 64); err == nil {
					freePages = pages
				}
			}
		} else if strings.HasPrefix(line, "Pages inactive:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				// Remove trailing period
				numStr := strings.TrimSuffix(fields[2], ".")
				if pages, err := strconv.ParseUint(numStr, 10, 64); err == nil {
					inactivePages = pages
				}
			}
		}
	}

	return (freePages + inactivePages) * pageSize
}
