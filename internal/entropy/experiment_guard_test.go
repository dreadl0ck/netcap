//go:build entropyexperiment && darwin && arm64 && !purego

package entropy

import (
	"syscall"
	"testing"
)

func TestExperimentGuardPage(t *testing.T) {
	page := syscall.Getpagesize()
	data, err := syscall.Mmap(-1, 0, 2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(data)
	for i := range data[:page] {
		data[i] = byte(i)
	}
	if err := syscall.Mprotect(data[page:], syscall.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	for n := 0; n <= page; n++ {
		checkExperiment(t, data[page-n:page:page])
	}
}
