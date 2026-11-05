package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUnknownRootCommand(t *testing.T) {
	if os.Getenv("NETCAP_UNKNOWN_COMMAND_CHILD") == "1" {
		os.Args = []string{"net", "version"}
		main()
		return
	}
	c := exec.Command(os.Args[0], "-test.run=^TestUnknownRootCommand$")
	c.Env = append(os.Environ(), "NETCAP_UNKNOWN_COMMAND_CHILD=1")
	b, err := c.CombinedOutput()
	if err == nil || !strings.Contains(string(b), "unknown command") || strings.Contains(string(b), "\x1b[2J") {
		t.Fatal("unknown command did not fail cleanly")
	}
}
