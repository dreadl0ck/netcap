//go:build darwin

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

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
