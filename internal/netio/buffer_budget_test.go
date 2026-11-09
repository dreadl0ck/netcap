package netio

import (
	"fmt"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBufferBudgetAndLargeRecord(t *testing.T) {
	w := newProtoWriter(&WriterConfig{Out: t.TempDir(), Name: "Kerberos", Type: types.Type_NC_Kerberos, Buffer: true})
	if w.bWriter != nil {
		t.Fatal("unused protocol allocated a data buffer")
	}
	if err := w.WriteHeader(types.Type_NC_Kerberos); err != nil {
		t.Fatal(err)
	}
	record := &types.Kerberos{Timestamp: 1, ClientName: strings.Repeat("x", 1<<20)}
	if err := w.Write(record); err != nil {
		t.Fatal(err)
	}
	if w.bWriter.Size() > 128<<10 {
		t.Fatalf("per-decoder buffer budget exceeded: %d", w.bWriter.Size())
	}
	name, _ := w.Close(1)
	r, err := Open(filepath.Join(w.wc.Out, name), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	got := &types.Kerberos{}
	if err := r.Next(got); err != nil || got.ClientName != record.ClientName {
		t.Fatalf("record larger than buffer corrupted: %v", err)
	}
}

func TestHeaderOnlyWriterIsLazyUntilExplicitFlush(t *testing.T) {
	w := newProtoWriter(&WriterConfig{Out: t.TempDir(), Name: "TCP", Type: types.Type_NC_TCP, Buffer: true, Compress: true, CompressionLevel: 1, CompressionBlockSize: 1 << 20})
	if err := w.WriteHeader(types.Type_NC_TCP); err != nil {
		t.Fatal(err)
	}
	if w.initialized || w.gWriter != nil || w.bWriter != nil {
		t.Fatal("unused protocol allocated compression state")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(w.file.Name(), 0)
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.ReadHeader()
	_ = r.Close()
	if err != nil || h.Type != types.Type_NC_TCP {
		t.Fatal("live header was not published", err)
	}
	path := w.file.Name()
	w.Close(0)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("header-only output retained", err)
	}
}

func BenchmarkDefaultAuditWriterMemory(b *testing.B) {
	for _, size := range []int{12 << 20, defaults.BufferSize} {
		b.Run(fmt.Sprintf("buffer-%d", size), func(b *testing.B) {
			dir := b.TempDir()
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				var writers []*protoWriter
				for i := 0; i < 8; i++ {
					w := newProtoWriter(&WriterConfig{Out: dir, Name: fmt.Sprint(i), Buffer: true, MemBufferSize: size})
					if err := w.WriteHeader(types.Type_NC_Kerberos); err != nil {
						b.Fatal(err)
					}
					if err := w.Write(&types.Kerberos{Timestamp: 1, ClientName: "analyst"}); err != nil {
						b.Fatal(err)
					}
					writers = append(writers, w)
				}
				for _, w := range writers {
					w.Close(1)
				}
			}
		})
	}
}
