package netio

import (
	"bytes"
	"encoding/csv"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestCSVPreservesRawHTTPFields(t *testing.T) {
	r := &types.HTTP{URL: "/a,b%2F?q=x,y", UserAgent: "test,\"quoted\"\nnext"}
	var buf bytes.Buffer
	w := newCSVProtoWriter(&buf, false, false, nil)
	if _, err := w.writeRecord(r); err != nil {
		t.Fatal(err)
	}
	fields, err := csv.NewReader(&buf).Read()
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range r.CSVHeader() {
		if name == "URL" && fields[i] != r.URL || name == "UserAgent" && fields[i] != r.UserAgent {
			t.Fatal(name, fields[i])
		}
	}
	if r.URL != "/a,b%2F?q=x,y" {
		t.Fatal("record mutated")
	}
}
