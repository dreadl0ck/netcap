package filter

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestInListMatchesIOCFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_IOC_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "sha256.txt"), []byte("# feed\n  ABCDEF0123  \n\n198.51.100.7\nevil.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for value, want := range map[string]bool{"abcdef0123": true, "ABCDEF0123": true, "198.51.100.7": true, "Evil.Example": true, "good.example": false, "": false} {
		if got := InList(value, "sha256.txt"); got != want {
			t.Errorf("InList(%q) = %v", value, got)
		}
	}
	for _, name := range []string{"../etc/passwd", "/etc/passwd", "sub/list.txt", "missing.txt", ""} {
		if InList("abcdef0123", name) {
			t.Errorf("%q matched", name)
		}
	}
	if ValidateIOCList("missing.txt") == nil || ValidateIOCList("../x") == nil || ValidateIOCList("sha256.txt") != nil {
		t.Fatal("validation")
	}
	program, err := CompileExpression(`InList(DstIP, "sha256.txt")`, types.Type_NC_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := EvaluateExpression(program, &types.TCP{DstIP: "198.51.100.7"}); !ok || err != nil {
		t.Fatal("rule did not match", ok, err)
	}
}

func TestInListOnAbsentNestedMessage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_IOC_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "hashes.txt"), []byte("aa11\n"), 0600); err != nil {
		t.Fatal(err)
	}
	program, err := CompileExpression(`InList(Hashes?.SHA256, "hashes.txt")`, types.Type_NC_File)
	if err != nil {
		t.Fatal(err)
	}
	for record, want := range map[*types.File]bool{{}: false, {Hashes: &types.FileHashes{SHA256: "AA11"}}: true, {Hashes: &types.FileHashes{SHA256: "bb"}}: false} {
		if ok, err := EvaluateExpression(program, record); ok != want || err != nil {
			t.Errorf("%v: %v %v", record.Hashes, ok, err)
		}
	}
}

func TestInListRejectsSymlinkOutsideIOCDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_IOC_DIR", dir)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "feed.txt")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink: %v", err)
		}
		t.Fatal(err)
	}
	if InList("example.test", "feed.txt") || ValidateIOCList("feed.txt") == nil {
		t.Fatal("loaded feed outside IOC directory")
	}
}

func TestInListRefreshesReplacedFeedAndChangedDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_IOC_DIR", dir)
	const name = "feed.txt"
	path := filepath.Join(dir, name)
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(path, "old\n")
	if !InList("old", name) {
		t.Fatal("initial feed did not match")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.txt")
	write(replacement, "new\n")
	if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	iocMu.Lock()
	iocLists[name].checked = iocLists[name].checked.Add(-iocListRecheck)
	iocMu.Unlock()
	if !InList("new", name) || InList("old", name) {
		t.Fatal("did not refresh replaced feed")
	}
	other := t.TempDir()
	write(filepath.Join(other, name), "other\n")
	t.Setenv("NC_IOC_DIR", other)
	if !InList("other", name) || InList("new", name) {
		t.Fatal("reused cached feed from previous IOC directory")
	}
}

func TestReadIOCListByteLimit(t *testing.T) {
	const data = "a\n# comment\n"
	if entries, err := readIOCList(strings.NewReader(data), int64(len(data))); err != nil || len(entries) != 1 {
		t.Fatalf("feed at byte limit: %v, %v", entries, err)
	}
	if entries, err := readIOCList(strings.NewReader(data+"\n"), int64(len(data))); !errors.Is(err, errIOCListSize) || entries != nil {
		t.Fatalf("feed over byte limit: %v, %v", entries, err)
	}
}
