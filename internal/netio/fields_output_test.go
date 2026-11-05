package netio

import (
	"github.com/dreadl0ck/netcap/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFieldsDoesNotDumpRecordsInStructuredMode(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "HTTP.ncap")
	if err := writeSortedRun(input, &types.Header{Type: types.Type_NC_HTTP}, []timedRecord{&types.HTTP{Timestamp: 1, URL: "record-sentinel"}}); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(dir, "fields-")
	if err != nil {
		t.Fatal(err)
	}
	if err := Dump(out, DumpConfig{Path: input, Fields: true, Structured: true}); err != nil {
		t.Fatal(err)
	}
	_ = out.Close()
	b, err := os.ReadFile(out.Name())
	if err != nil || !strings.Contains(string(b), "URL\n") || !strings.Contains(string(b), "RequestHeader\n") || strings.Contains(string(b), "record-sentinel") {
		t.Fatal("field listing dumped data or omitted names", err)
	}
}
