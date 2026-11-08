//go:build !http3

package main

import (
	"strings"
	"testing"
)

const http3BuildTag = ""

func TestHTTP3UnavailableFailsStartup(t *testing.T) {
	config, _ := runtimeConfig(t, "http://127.0.0.1:1", freeAddress(t, "tcp"))
	if out, err := runCLI(t, "", "serve", "--config", config, "--http3-listen", freeAddress(t, "udp")); err == nil || !strings.Contains(out, "rebuild with -tags http3") {
		t.Fatalf("HTTP/3 startup: %v %s", err, out)
	}
}
