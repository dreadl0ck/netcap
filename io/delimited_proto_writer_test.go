package io

import (
	"bytes"
	"errors"
	"fmt"
	std "io"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/performance"
	"github.com/dreadl0ck/netcap/types"
)

func TestProtoWriterBufferReuse(t *testing.T) {
	var got, want bytes.Buffer
	w := &protoWriter{wc: &WriterConfig{PerfTracker: performance.NewTracker()}, pWriter: newDelimitedProtoWriter(delimited.NewWriter(&got))}
	baseline := delimited.NewWriter(&want)
	for _, size := range []int{0, 64, 65536, 17, 2 << 20, 32, 0} {
		msg := &types.TCP{SrcIP: "192.0.2.1", Payload: bytes.Repeat([]byte{'x'}, size)}
		if err := w.Write(msg); err != nil {
			t.Fatal(err)
		}
		if err := baseline.PutProto(msg); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatal("framed output differs from proto.Marshal baseline")
	}
}

func TestProtoWriterConcurrent(t *testing.T) {
	var output bytes.Buffer
	w := newDelimitedProtoWriter(delimited.NewWriter(&output))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 100 {
				if _, err := w.putProto(&types.TCP{SrcIP: fmt.Sprintf("%d:%d", i, j)}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	r := delimited.NewReader(&output)
	seen := make(map[string]bool)
	for range 800 {
		data, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		var msg types.TCP
		if err := proto.Unmarshal(data, &msg); err != nil {
			t.Fatal(err)
		}
		if seen[msg.SrcIP] {
			t.Fatalf("duplicate record %q", msg.SrcIP)
		}
		seen[msg.SrcIP] = true
	}
	if _, err := r.Next(); err != std.EOF {
		t.Fatalf("trailing read = %v, want EOF", err)
	}
}

type fallbackProto struct {
	err error
}

func (*fallbackProto) Reset()         {}
func (*fallbackProto) String() string { return "fallback" }
func (*fallbackProto) ProtoMessage()  {}
func (m *fallbackProto) Marshal() ([]byte, error) {
	return []byte{8, 1}, m.err
}

type failingSizedProto struct{ fallbackProto }

func (*failingSizedProto) Size() int { return 1 }
func (m *failingSizedProto) MarshalToSizedBuffer([]byte) (int, error) {
	return 0, m.err
}

type failingProtoSink struct {
	calls  int
	failAt int
	err    error
}

func (w *failingProtoSink) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, w.err
	}
	return len(p), nil
}

func TestDelimitedProtoWriterFallbackAndErrors(t *testing.T) {
	encodingErr := errors.New("encoding failed")
	for _, msg := range []proto.Message{
		&fallbackProto{}, &fallbackProto{err: encodingErr},
		&failingSizedProto{fallbackProto{err: encodingErr}},
		&types.TCP{}, nil,
	} {
		t.Run(fmt.Sprintf("%T/%v", msg, msg), func(t *testing.T) {
			var got, want bytes.Buffer
			w := newDelimitedProtoWriter(delimited.NewWriter(&got))
			n, err := w.putProto(msg)
			baselineErr := delimited.NewWriter(&want).PutProto(msg)
			if (err == nil) != (baselineErr == nil) {
				t.Fatalf("error = %v, baseline = %v", err, baselineErr)
			}
			if baselineErr != nil {
				if err.Error() != baselineErr.Error() || got.Len() != 0 {
					t.Fatalf("encoding failure differs: error %v, output %x", err, got.Bytes())
				}
				return
			}
			record, _ := proto.Marshal(msg)
			if n != len(record) || !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Fatalf("size or output differs from baseline: size %d, want %d", n, len(record))
			}
		})
	}
	for _, failAt := range []int{1, 2} {
		writeErr := errors.New("write failed")
		w := newDelimitedProtoWriter(delimited.NewWriter(&failingProtoSink{failAt: failAt, err: writeErr}))
		if _, err := w.putProto(&types.TCP{SrcIP: "192.0.2.1"}); !errors.Is(err, writeErr) {
			t.Fatalf("write %d: error = %v, want %v", failAt, err, writeErr)
		}
	}
}

func TestDelimitedProtoWriterBufferBound(t *testing.T) {
	w := newDelimitedProtoWriter(delimited.NewWriter(std.Discard))
	for _, size := range []int{64, maxProtoBufferSize, 32, maxProtoBufferSize * 2, 0} {
		msg := &types.TCP{Payload: make([]byte, size)}
		n, err := w.putProto(msg)
		if err != nil || n != proto.Size(msg) {
			t.Fatalf("size %d: encoded %d, error %v", size, n, err)
		}
		if cap(w.buffer) > maxProtoBufferSize {
			t.Fatalf("retained %d bytes, limit %d", cap(w.buffer), maxProtoBufferSize)
		}
	}
}

func BenchmarkProtoWriter(b *testing.B) {
	for _, size := range []int{0, 1400, 65536} {
		b.Run(fmt.Sprintf("payload_%d", size), func(b *testing.B) {
			msg := &types.TCP{SrcIP: "192.0.2.1", DstIP: "198.51.100.1", SrcPort: 443, DstPort: 50000, Payload: make([]byte, size)}
			w := &protoWriter{wc: &WriterConfig{}, pWriter: newDelimitedProtoWriter(delimited.NewWriter(std.Discard))}
			b.ReportAllocs()
			b.SetBytes(int64(proto.Size(msg)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := w.Write(msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
