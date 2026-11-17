package netio

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func writerTestConfig(t *testing.T, kind string, buffer, compress bool) *WriterConfig {
	t.Helper()
	return &WriterConfig{Out: t.TempDir(), Name: "UDP", Type: types.Type_NC_UDP, Proto: kind == "proto", JSON: kind == "json", CSV: kind == "csv", Buffer: buffer, Compress: compress, MemBufferSize: 1024, CompressionBlockSize: 1 << 20}
}

func TestFailedCompressedWritersReleaseWorkers(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 32 {
		w := newProtoWriter(writerTestConfig(t, "proto", true, true))
		if err := w.WriteHeader(types.Type_NC_UDP); err != nil {
			t.Fatal(err)
		}
		if err := w.Write(&types.UDP{SrcPort: 123}); err != nil {
			t.Fatal(err)
		}
		if err := w.file.Close(); err != nil {
			t.Fatal(err)
		}
		w.Close(1)
		if WriterError(w) == nil {
			t.Fatal("compression failure was not exercised")
		}
	}
	if remaining := runtime.NumGoroutine() - before; remaining > 8 {
		t.Fatal("failed output retained compressor workers", remaining)
	}
}

func writerFile(w AuditRecordWriter) *os.File {
	switch typed := w.(type) {
	case *protoWriter:
		return typed.file
	case *jsonWriter:
		return typed.file
	case *csvWriter:
		return typed.file
	}
	return nil
}

func TestFileWritersRetainFinalizationErrors(t *testing.T) {
	for _, kind := range []string{"proto", "json", "csv"} {
		for _, buffer := range []bool{false, true} {
			for _, compress := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/buffer=%v/compress=%v", kind, buffer, compress), func(t *testing.T) {
					w := NewAuditRecordWriter(writerTestConfig(t, kind, buffer, compress))
					if err := w.WriteHeader(types.Type_NC_UDP); err != nil {
						t.Fatal(err)
					}
					if err := w.Write(&types.UDP{SrcPort: 123, DstPort: 456}); err != nil {
						t.Fatal(err)
					}
					if err := writerFile(w).Close(); err != nil {
						t.Fatal(err)
					}
					w.Close(1)
					if err := WriterError(w); !errors.Is(err, os.ErrClosed) {
						t.Fatal("closed output was reported successfully finalized", err)
					}
				})
			}
		}
	}
}

func TestFileWritersRetainRecordErrors(t *testing.T) {
	for _, kind := range []string{"proto", "json", "csv"} {
		t.Run(kind, func(t *testing.T) {
			w := NewAuditRecordWriter(writerTestConfig(t, kind, false, false))
			if err := w.WriteHeader(types.Type_NC_UDP); err != nil {
				t.Fatal(err)
			}
			if err := writerFile(w).Close(); err != nil {
				t.Fatal(err)
			}
			err := w.Write(&types.UDP{SrcPort: 123})
			if !errors.Is(err, os.ErrClosed) || WriterError(w) != err {
				t.Fatal("record failure was not retained", err, WriterError(w))
			}
			if next := w.Write(&types.UDP{SrcPort: 456}); next != err {
				t.Fatal("failed writer resumed", next)
			}
			w.Close(1)
			if WriterError(w) != err {
				t.Fatal("finalization replaced the original record failure")
			}
		})
	}
}

func TestSharedObservedWriterRetainsFailureAfterRegistryRemoval(t *testing.T) {
	cfg := writerTestConfig(t, "proto", true, true)
	a := GetSharedAuditRecordWriter(cfg).(*sharedWriter)
	b := GetSharedAuditRecordWriter(cfg).(*sharedWriter)
	observed := ObserveWriter(a, func(proto.Message) {})
	if err := a.WriteHeader(types.Type_NC_UDP); err != nil {
		t.Fatal(err)
	}
	if err := observed.Write(&types.UDP{SrcPort: 123}); err != nil {
		t.Fatal(err)
	}
	if err := writerFile(a.entry.writer).Close(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, writer := range []AuditRecordWriter{observed, b} {
		wg.Add(1)
		go func() { defer wg.Done(); writer.Close(1) }()
	}
	wg.Wait()
	for _, writer := range []AuditRecordWriter{a, b, observed} {
		if !errors.Is(WriterError(writer), os.ErrClosed) {
			t.Fatal("wrapper lost finalization error", WriterError(writer))
		}
	}
	replacement := GetSharedAuditRecordWriter(cfg)
	if WriterError(replacement) != nil {
		t.Fatal("new writer inherited a previous generation's failure")
	}
	if err := replacement.WriteHeader(types.Type_NC_UDP); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Write(&types.UDP{SrcPort: 789}); err != nil {
		t.Fatal(err)
	}
	replacement.Close(1)
	if WriterError(replacement) != nil {
		t.Fatal("healthy replacement failed", WriterError(replacement))
	}
}
