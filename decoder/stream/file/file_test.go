package file

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/gogo/protobuf/proto"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// withDecoderConfig installs the decoder configuration the collector sets up in
// production, so these tests exercise the real code path.
func withDecoderConfig(t *testing.T) {
	t.Helper()
	previous := decoderconfig.Instance
	decoderconfig.Instance = &decoderconfig.Config{}
	t.Cleanup(func() { decoderconfig.Instance = previous })
}

type countingWriter struct {
	written int64
	err     error
}

func (w *countingWriter) Write(msg proto.Message) error {
	atomic.AddInt64(&w.written, 1)
	return w.err
}

func (w *countingWriter) WriteHeader(t types.Type) error { return nil }
func (w *countingWriter) Close(int64) (string, int64)    { return "", 0 }
func (w *countingWriter) Flush() error                   { return nil }

// File extraction is driven by the protocol decoders, so WriteFile is reached
// whenever a transfer is seen even if the File decoder itself was never
// selected. That used to dereference a nil writer and take down the process
// mid-capture.
func TestWriteFileWithoutWriter(t *testing.T) {
	withDecoderConfig(t)
	Decoder.Writer = nil
	Decoder.NumRecordsWritten = 0
	t.Cleanup(func() { Decoder.Writer = nil; Decoder.NumRecordsWritten = 0 })

	WriteFile(&types.File{Name: "no-writer"})
	WriteFileEnhanced(&types.File{Name: "no-writer"})

	if got := atomic.LoadInt64(&Decoder.NumRecordsWritten); got != 0 {
		t.Fatalf("counted %d records without a writer", got)
	}
}

func TestWriteFileWithWriter(t *testing.T) {
	withDecoderConfig(t)
	w := &countingWriter{}
	Decoder.Writer = w
	Decoder.NumRecordsWritten = 0
	t.Cleanup(func() { Decoder.Writer = nil; Decoder.NumRecordsWritten = 0 })

	WriteFile(&types.File{Name: "a"})
	WriteFileEnhanced(&types.File{Name: "b"})

	if got := atomic.LoadInt64(&w.written); got != 2 {
		t.Fatalf("wrote %d records, want 2", got)
	}
	if got := atomic.LoadInt64(&Decoder.NumRecordsWritten); got != 2 {
		t.Fatalf("counted %d records, want 2", got)
	}
}

// A failing writer must not terminate the capture either.
func TestWriteFileWriterError(t *testing.T) {
	withDecoderConfig(t)
	w := &countingWriter{err: errors.New("disk full")}
	Decoder.Writer = w
	Decoder.NumRecordsWritten = 0
	t.Cleanup(func() { Decoder.Writer = nil; Decoder.NumRecordsWritten = 0 })

	WriteFile(&types.File{Name: "a"})

	if got := atomic.LoadInt64(&w.written); got != 1 {
		t.Fatalf("wrote %d records, want 1", got)
	}
}
