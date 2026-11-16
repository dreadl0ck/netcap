//go:build integration

package integration

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/dreadl0ck/netcap/types"
)

func TestRecheck168NonUTF8MetadataRetainsHTTPPair(t *testing.T) {
	out := t.TempDir()
	if err := processWithCollector(testutil.Recheck168Capture(t, "http_nonutf8.pcap"), out); err != nil {
		t.Fatal(err)
	}
	reader, err := netio.Open(filepath.Join(out, "HTTP.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	record := &types.HTTP{}
	if err := reader.Next(record); err != nil {
		t.Fatal(err)
	}
	if record.Method != "GET" || record.StatusCode != 200 || !strings.Contains(strings.Join(record.ParseQualifications, ","), "invalid-http-metadata-value") {
		t.Fatalf("qualified pair missing: %+v", record)
	}
	if !bytes.Contains(record.RawRequestLine, []byte{0xff, 0xfe}) {
		t.Fatal("non-UTF8 request target bytes lost")
	}
	found := false
	for _, header := range record.RequestHeaders {
		if bytes.Equal(header.Name, []byte("User-Agent")) && bytes.ContainsRune(header.Value, 0) {
			found = true
		}
	}
	if !found {
		t.Fatal("NUL metadata evidence lost")
	}
	if err := reader.Next(new(types.HTTP)); err != io.EOF {
		t.Fatal("transaction remains split", err)
	}
}
