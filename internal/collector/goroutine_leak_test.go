package collector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime/pprof"
	"testing"
	"time"
)

func captureGoroutineLeakProfile(t *testing.T) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutineleak").WriteTo(&buf, 1); err != nil {
		t.Fatal(err)
	}
	var count int
	if _, err := fmt.Sscanf(buf.String(), "goroutineleak profile: total %d", &count); err != nil {
		t.Fatalf("parse goroutine leak profile: %v\n%s", err, buf.String())
	}
	return count, buf.String()
}

func TestGoroutineLeakProfileDetectsBlockedChannel(t *testing.T) {
	const child = "NETCAP_TEST_LEAK_PROFILE_CHILD"
	if os.Getenv(child) != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestGoroutineLeakProfileDetectsBlockedChannel$", "-test.count=1")
		cmd.Env = append(os.Environ(), child+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("leak profiler control failed (timeout: %v): %v\n%s", ctx.Err(), err, output)
		}
		return
	}

	ready := make(chan struct{})
	go func() {
		close(ready)
		<-make(chan struct{})
	}()
	<-ready
	deadline := time.Now().Add(5 * time.Second)
	for {
		count, profile := captureGoroutineLeakProfile(t)
		if count > 0 {
			if !bytes.Contains([]byte(profile), []byte("TestGoroutineLeakProfileDetectsBlockedChannel")) {
				t.Fatalf("leak profile misses control goroutine:\n%s", profile)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("blocked channel was not reported:\n%s", profile)
		}
	}
}
