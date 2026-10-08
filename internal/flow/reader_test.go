package flow

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestFlowReaderRejectsOversizedRecordBeforePayloadRead(t *testing.T) {
	var source bytes.Buffer
	if err := delimited.NewWriter(&source).PutProto(&types.Header{Type: types.Type_NC_Connection}); err != nil {
		t.Fatal(err)
	}
	var size [10]byte
	n := binary.PutUvarint(size[:], 4<<20+1)
	source.Write(size[:n])
	path := filepath.Join(t.TempDir(), "Connection.ncap")
	if err := os.WriteFile(path, source.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	q := Query{StartNs: 0, EndNs: 1, GroupBy: "srcIP", SortBy: "bytes", Limit: 10}
	if _, err := ReadFile(context.Background(), path, q); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized header reached payload parsing: %v", err)
	}
}
