//go:build linux

package enforcer

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const nftLockDirectory = "netcap-enforcer"

// Directory-relative opens pin the root-owned directory and reject symlinks at
// every configurable-free path component. Keys deliberately exclude scope, token,
// namespace name and state path: these must never partition table ownership.
func lockNFT(namespace os.FileInfo, table string) (*os.File, error) {
	identity, ok := namespace.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("cannot identify network namespace")
	}
	run, err := syscall.Open("/run", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(run)
	if err = checkLockNode(run, syscall.S_IFDIR, 0755, false); err != nil {
		return nil, err
	}
	if err = syscall.Mkdirat(run, nftLockDirectory, 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, err
	}
	dir, err := syscall.Openat(run, nftLockDirectory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dir)
	if err = checkLockNode(dir, syscall.S_IFDIR, 0700, true); err != nil {
		return nil, err
	}
	key := fmt.Sprintf("net-%x-%x-inet-%s.lock", identity.Dev, identity.Ino, table)
	fd, err := syscall.Openat(dir, key, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), key)
	if err = checkLockNode(fd, syscall.S_IFREG, 0600, true); err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("nft namespace/table ownership unavailable: %w", err)
	}
	return f, nil
}

func checkLockNode(fd int, kind uint32, mode uint32, exact bool) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 || stat.Mode&syscall.S_IFMT != kind || stat.Mode&0022 != 0 {
		return errors.New("nft lock path must be root-owned, expected type, and not group/world writable")
	}
	if exact && (stat.Mode&07777 != mode || (kind == syscall.S_IFREG && stat.Nlink != 1)) {
		return errors.New("nft lock directory/file must be private (0700/0600), without hard links")
	}
	return nil
}
