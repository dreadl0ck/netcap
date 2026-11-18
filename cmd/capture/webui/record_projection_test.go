package webui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestCompleteAuditRecordsPreserveHeadersAndBoundPages(t *testing.T) {
	value := strings.Repeat("header", 10000)
	rows := []proto.Message{}
	for range 5 {
		rows = append(rows, &types.HTTP{Method: "GET", RequestHeader: map[string]string{"X-Large": value}})
	}
	file := writeTimelineAuditFile(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, rows)
	for _, query := range []string{"full=true&limit=500", "full=true&limit=1&fields=Method,RequestHeader", "full=true&limit=1&fields=/RequestHeader/X-Large"} {
		w := httptest.NewRecorder()
		HandleAuditStream(w, httptest.NewRequest("GET", "/?"+query, nil), file, "HTTP")
		body := w.Body.String()
		if strings.Contains(body, "_truncated") || strings.Contains(body, "event: error") || !strings.Contains(body, value) {
			t.Fatal("structured header was lost")
		}
		if !strings.Contains(body, `"total": 5`) || !strings.Contains(body, `"hasMore": true`) {
			t.Fatal("missing page continuation", body[len(body)-250:])
		}
		if len(body) > 200<<10 {
			t.Fatal("unbounded page", len(body))
		}
	}
}

func BenchmarkRecordProjectionWideRow(b *testing.B) {
	raw := []byte(`{"Timestamp":9223372036854775807,"Method":"GET","Host":"fixture","Src":"192.0.2.1","headers":[{"key":"value"}],"body":"` + strings.Repeat("x", 256<<10) + `"}`)
	projection, err := parseRecordProjection("Timestamp,Method,Host,Src,/headers/0/key")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := applyRecordProjection(raw, projection); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecordProjectionNestedRow(b *testing.B) {
	raw := []byte(`{"records":[{"Timestamp":9223372036854775807,"Method":"GET","Host":"fixture","Src":"192.0.2.1","body":"` + strings.Repeat("x", 256<<10) + `"}]}`)
	projection, err := parseRecordProjection("/records/0/Timestamp,/records/0/Method,/records/0/Host,/records/0/Src")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := applyRecordProjection(raw, projection); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRecordProjectionPreservesExactValues(t *testing.T) {
	raw := []byte(`{"Timestamp":9223372036854775807,"headers":[{"a/b~c":"value","n":9223372036854775807}]}`)
	out, err := projectRecordJSON(raw, "Timestamp,/headers/0/a~1b~0c,/headers/0/n")
	if err != nil || !strings.Contains(string(out), "9223372036854775807") {
		t.Fatal(string(out), err)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(out, &values); err != nil {
		t.Fatal(err)
	}
	if string(values["/headers/0/a~1b~0c"]) != `"value"` || string(values["/headers/0/n"]) != "9223372036854775807" {
		t.Fatal(string(out))
	}
	for _, bad := range []string{"missing", "/headers/3", "/headers/-1", "Timestamp,", strings.Repeat("Timestamp,", 33) + "Timestamp", "/a/b/c/d/e/f/g/h/i"} {
		if _, err := projectRecordJSON(raw, bad); err == nil {
			t.Fatal("invalid projection accepted", bad)
		}
	}
}
