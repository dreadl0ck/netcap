package delimited

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReaderLimitRejectsLengthBeforeAllocation(t *testing.T) {
	var length [10]byte
	n := binary.PutUvarint(length[:], 1<<63)
	reader := NewReaderWithLimit(bytes.NewReader(length[:n]), 1<<20)
	if _, err := reader.Next(); err == nil || !strings.Contains(err.Error(), "exceeds limit") || cap(reader.data) != 0 {
		t.Fatalf("oversized frame allocated or not rejected: %v", err)
	}
}
