//go:build windows && !nomagika

package magika

import "os/exec"

func configureProcess(cmd *exec.Cmd) {}
