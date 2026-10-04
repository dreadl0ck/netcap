package webui

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// A categorical sankey used to recurse GenerateChart -> GenerateChartFromDirs
// until the goroutine stack overflowed, which is fatal and killed the server.
func TestCategoricalSankeyRenders(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "Connection.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*types.Connection{
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", CommunityID: "a", TimestampFirst: 1},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.3", CommunityID: "b", TimestampFirst: 2},
	} {
		if err := w.PutProto(c); err != nil {
			t.Fatal(err)
		}
	}
	gz.Close()
	f.Close()

	out, err := NewChartGenerator("Connection", "CommunityID", "sankey", "", false, 100).GenerateChart(dir)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(out)
	if !strings.Contains(string(html), "sankey") {
		t.Fatalf("no sankey in output (%d bytes)", len(html))
	}
}
