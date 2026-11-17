package delimited

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestTruncatedLargeFrameDoesNotAllocateDeclaredLength(t *testing.T) {
	for _, received := range []int{0, 9000} {
		wire := append(binary.AppendUvarint(nil, 128<<20), make([]byte, received)...)
		reader := NewReader(bytes.NewReader(wire))
		if _, err := reader.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("received %d bytes: %v", received, err)
		}
		if cap(reader.data) > 2*received {
			t.Fatalf("received %d bytes but allocated %d", received, cap(reader.data))
		}
	}
}

func TestReaderLimitRejectsLengthBeforeAllocation(t *testing.T) {
	var length [10]byte
	n := binary.PutUvarint(length[:], 1<<63)
	reader := NewReaderWithLimit(bytes.NewReader(length[:n]), 1<<20)
	if _, err := reader.Next(); err == nil || !strings.Contains(err.Error(), "exceeds limit") || cap(reader.data) != 0 {
		t.Fatalf("oversized frame allocated or not rejected: %v", err)
	}
}
