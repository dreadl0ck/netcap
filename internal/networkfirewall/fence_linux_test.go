//go:build linux

package networkfirewall

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFenceFDHelper(t *testing.T) {
	n := os.Getenv("NFW_FENCE_NAMESPACE")
	if n == "" {
		return
	}
	ns, err := openNamespace(n)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	fd, err := kernelFence(ns)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "fence")
	defer f.Close()
	child := exec.Command("sleep", "60")
	child.ExtraFiles = []*os.File{f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, child.Process.Pid)
}

func TestFenceFDLab(t *testing.T) {
	if os.Getenv("NETCAP_NETWORKFIREWALL_LAB") != "1" {
		t.Skip("disposable Linux Docker lab only")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal(err)
	}
	const namespace = "nfw-fence"
	if out, err := exec.Command("ip", "netns", "add", namespace).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	defer exec.Command("ip", "netns", "del", namespace).Run()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(exe, "-test.run=^TestFenceFDHelper$")
	c.Env = append(os.Environ(), "NFW_FENCE_NAMESPACE="+namespace)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatal("missing FD-holder PID")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Kill(pid, unix.SIGKILL)
	ns, err := openNamespace(namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	// The creator has exited. A surviving inherited FD must still fence the
	// namespace, even though no original owner PID remains to check.
	if fd, err := kernelFence(ns); err == nil {
		unix.Close(fd)
		t.Fatal("inherited lifetime FD did not exclude a second owner")
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if fd, err := kernelFence(ns); err == nil {
			unix.Close(fd)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("kernel fence remained after last FD closed")
}
