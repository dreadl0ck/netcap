//go:build darwin && appstore

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

/*
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_host.h>

// total_memory returns hw.memsize via sysctlbyname, 0 on failure. No process
// is spawned; this is a direct syscall, sandbox-safe under the App Store.
static unsigned long long total_memory(void) {
    unsigned long long mem = 0;
    size_t len = sizeof(mem);
    if (sysctlbyname("hw.memsize", &mem, &len, NULL, 0) != 0) {
        return 0;
    }
    return mem;
}

// free_memory returns (free + inactive) pages * page size via
// host_statistics64, matching what the vm_stat parser reported. 0 on failure.
static unsigned long long free_memory(void) {
    mach_port_t host = mach_host_self();

    vm_size_t page_size = 0;
    if (host_page_size(host, &page_size) != KERN_SUCCESS || page_size == 0) {
        page_size = 4096;
    }

    vm_statistics64_data_t vmstat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&vmstat, &count) != KERN_SUCCESS) {
        return 0;
    }

    unsigned long long pages = (unsigned long long)vmstat.free_count +
                               (unsigned long long)vmstat.inactive_count;
    return pages * (unsigned long long)page_size;
}
*/
import "C"

// getTotalMemoryOS returns the total system memory in bytes for macOS using a
// cgo sysctlbyname call. The App Store edition spawns no sysctl process.
func getTotalMemoryOS() uint64 {
	return uint64(C.total_memory())
}

// getFreeMemoryOS returns the free system memory in bytes for macOS using a
// cgo host_statistics64 call. The App Store edition spawns no vm_stat process.
func getFreeMemoryOS() uint64 {
	return uint64(C.free_memory())
}
