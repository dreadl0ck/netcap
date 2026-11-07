//go:build !nomagika && !windows

package magika

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoundedClassifierProcess(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		deadline     time.Duration
		want         string
	}{
		{"valid", `printf '%s' '[{"result":{"status":"ok","value":{"output":{"label":"text","mime_type":"text/plain","is_text":true},"score":0.99}}}]'`, 30 * time.Second, ""},
		{"invalid-json", `printf nope`, 10 * time.Second, "invalid"},
		{"empty", `printf '[]'`, 10 * time.Second, "no successful"},
		{"exit", `exit 3`, 30 * time.Second, "process"},
		{"stdout-budget", `/usr/bin/head -c 1100000 /dev/zero`, 10 * time.Second, "output limit"},
		{"stderr-budget", `/usr/bin/head -c 70000 /dev/zero >&2`, 10 * time.Second, "output limit"},
		{"timeout", `/bin/sleep 10`, 20 * time.Millisecond, "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "magika")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", filepath.Dir(path))
			classifier, err := NewClassifier()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), tc.deadline)
			defer cancel()
			started := time.Now()
			result, err := classifier.ClassifyBytes(ctx, []byte("owned fixture"))
			if tc.want == "" {
				if err != nil || result == nil || result.Label != "text" {
					t.Fatalf("classification: %+v %v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %s error, got %v", tc.want, err)
			}
			if tc.name == "timeout" && (!errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second) {
				t.Fatal("process cancellation unbounded")
			}
		})
	}
}
