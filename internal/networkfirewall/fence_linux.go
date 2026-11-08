//go:build linux

package networkfirewall

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Abstract AF_UNIX addresses belong to the network namespace, independent of
// /run mounts and PIDs. The kernel releases this socket only after its last FD.
func kernelFence(ns *os.File) (fd int, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := unix.Open("/proc/self/task/"+fmt.Sprint(unix.Gettid())+"/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(original)
	if err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
		return -1, err
	}
	defer func() {
		if e := unix.Setns(original, unix.CLONE_NEWNET); e != nil {
			// Returning this thread to Go would run unrelated work in the target.
			panic(fmt.Sprintf("restore network namespace: %v", e))
		}
	}()
	fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: "@netcap.networkfirewall.packet-owner.v1"}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("kernel packet-owner fence unavailable: %w", err)
	}
	return fd, nil
}
