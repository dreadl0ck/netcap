package netio

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

func TestCSVCompressionLifecycle(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, compressed := range []bool{false, true} {
			for _, count := range []int{1, 20000} {
				t.Run(fmt.Sprintf("buffer=%t/compress=%t/rows=%d", buffered, compressed, count), func(t *testing.T) {
					out := t.TempDir()
					w := newCSVWriter(&WriterConfig{Out: out, Name: "TCP", Type: types.Type_NC_TCP, Buffer: buffered, Compress: compressed, MemBufferSize: 4096, CompressionLevel: gzip.BestSpeed, CompressionBlockSize: defaults.CompressionBlockSize})
					if err := w.WriteHeader(types.Type_NC_TCP); err != nil {
						t.Fatal(err)
					}
					for i := range count {
						if err := w.Write(sampleTCP(i)); err != nil {
							t.Fatal(err)
						}
						if i == count/2 {
							if err := w.Flush(); err != nil {
								t.Fatal(err)
							}
						}
					}
					name, size := w.Close(int64(count))
					if size <= 0 {
						t.Fatal("empty CSV", name)
					}
					f, err := os.Open(filepath.Join(out, name))
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					var source io.Reader = f
					if compressed {
						gz, err := gzip.NewReader(f)
						if err != nil {
							t.Fatal(err)
						}
						defer gz.Close()
						source = gz
					}
					rows, err := csv.NewReader(source).ReadAll()
					if err != nil {
						t.Fatal("CSV/gzip integrity:", err)
					}
					if len(rows) != count+1 {
						t.Fatalf("got %d rows; want %d", len(rows), count+1)
					}
				})
			}
		}
	}
}
