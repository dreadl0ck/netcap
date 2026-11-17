package delimited

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestSkipLargeFrameWithoutBodyBuffer(t *testing.T) {
	const size = 32 << 20
	header := binary.AppendUvarint(nil, size)
	r := NewReader(io.MultiReader(bytes.NewReader(header), io.LimitReader(zeros{}, size), bytes.NewReader([]byte{1, 42})))
	if err := r.Skip(context.Background()); err != nil || cap(r.data) != 0 {
		t.Fatalf("skip allocated a body or failed: cap=%d err=%v", cap(r.data), err)
	}
	if data, err := r.Next(); err != nil || !bytes.Equal(data, []byte{42}) {
		t.Fatal(data, err)
	}
	r = NewReader(bytes.NewReader(header))
	if err := r.Skip(context.Background()); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Skip(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
