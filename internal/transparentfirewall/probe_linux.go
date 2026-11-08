//go:build linux

package transparentfirewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// socketInNamespace enters only to create the socket. Restoration failure leaves
// the goroutine locked so the runtime destroys the contaminated thread on exit.
func socketInNamespace(ns *os.File, family int) (int, error) {
	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		original, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{-1, err}
			return
		}
		defer unix.Close(original)
		if err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- result{-1, err}
			return
		}
		fd, socketErr := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err = unix.Setns(original, unix.CLONE_NEWNET); err != nil {
			if fd >= 0 {
				unix.Close(fd)
			}
			done <- result{-1, err}
			return
		}
		runtime.UnlockOSThread()
		done <- result{fd, socketErr}
	}()
	r := <-done
	return r.fd, r.err
}

func probe(ctx context.Context, ns *os.File, a netip.Addr, port int) error {
	family := unix.AF_INET6
	var target unix.Sockaddr = &unix.SockaddrInet6{Port: port, Addr: a.As16()}
	if a.Is4() {
		family = unix.AF_INET
		target = &unix.SockaddrInet4{Port: port, Addr: a.As4()}
	}
	fd, err := socketInNamespace(ns, family)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, target)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EINPROGRESS) {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(poll, 25)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		code, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if code != 0 {
			return unix.Errno(code)
		}
		return nil
	}
}
