//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package enforcer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStateLockSurvivesFileButNotProcess(t *testing.T) {
	if path := os.Getenv("ENFORCER_TEST_LOCK_CHILD"); path != "" {
		if _, err := lockState(path); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Deliberately skip Close to exercise crash-style lock release.
	}
	path := filepath.Join(t.TempDir(), "state")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestStateLockSurvivesFileButNotProcess$")
	cmd.Env = append(os.Environ(), "ENFORCER_TEST_LOCK_CHILD="+path)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	if _, err = os.Stat(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockState(path)
	if err != nil {
		t.Fatal("dead process retained lock", err)
	}
	if err = unlock(); err != nil {
		t.Fatal(err)
	}
}
