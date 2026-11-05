package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLazyLogsRemainAbsentUntilWrittenAndReopenAfterSync(t *testing.T) {
	dir := t.TempDir()
	l, f, err := InitZapLogger(dir, "lazy", false)
	if err != nil || f != nil {
		t.Fatal(err)
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lazy.log")); !os.IsNotExist(err) {
		t.Fatal("empty file created")
	}
	l.Info("first")
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	l.Info("second")
	_ = l.Sync()
	b, err := os.ReadFile(filepath.Join(dir, "lazy.log"))
	if err != nil || !strings.Contains(string(b), "first") || !strings.Contains(string(b), "second") {
		t.Fatal("sync truncated log", err)
	}
}
