package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Per-stream output is written for every flow. A sync per file made
// stream-heavy captures spend minutes in fsync; durability comes from one
// barrier before completion (internal/durable).
func TestStreamOutputsDoNotSyncPerFile(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{".Sync()", "O_SYNC", "Fsync("} {
			if strings.Contains(string(source), forbidden) {
				t.Errorf("%s uses %s", name, forbidden)
			}
		}
	}
}
