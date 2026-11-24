package filter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestHTTPURLIOCChecksAuthorityAndPreservesPathCase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_IOC_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "urls.txt"), []byte("http://Files.Example/Download?q=A\n"), 0600); err != nil {
		t.Fatal(err)
	}
	program, err := CompileExpression(`HTTPURLInList(Host, URL, "urls.txt")`, types.Type_NC_HTTP)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, target string
		want         bool
	}{
		{"FILES.example.:80", "/Download?q=A", true},
		{"files.example", "http://files.example/Download?q=A", true},
		{"files.example", "/download?q=A", false},
		{"files.example", "/Download?q=a", false},
		{"other.example", "http://files.example/Download?q=A", false},
		{"files.example", "//files.example/Download?q=A", false},
	} {
		got, err := EvaluateExpression(program, &types.HTTP{Host: tc.host, URL: tc.target})
		if err != nil || got != tc.want {
			t.Errorf("%q %q: match=%v err=%v, want %v", tc.host, tc.target, got, err, tc.want)
		}
	}
}

func TestDomainAgeUsesCaptureTimeAndRejectsConflictingDates(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NC_IOC_DIR", dir)
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("dates.txt", "example.com 2020-06-01\n")
	write("conflict.txt", "example.com 2020-06-01\nexample.com 2020-06-02\n")
	timestamp := time.Date(2020, 6, 6, 13, 0, 0, 0, time.UTC).UnixNano()
	for _, tc := range []struct {
		host, file string
		at, want   int64
	}{
		{"sub.EXAMPLE.com.:443", "dates.txt", timestamp, 5},
		{"sub.example.com", "dates.txt", timestamp - int64(7*24*time.Hour), -1},
		{"example.com", "conflict.txt", timestamp, -1},
		{"unknown.example", "dates.txt", timestamp, -1},
		{"192.0.2.1", "dates.txt", timestamp, -1},
	} {
		if got := DomainAgeDays(tc.host, tc.at, tc.file); got != tc.want {
			t.Errorf("%q/%q: age=%d, want %d", tc.host, tc.file, got, tc.want)
		}
	}
}
