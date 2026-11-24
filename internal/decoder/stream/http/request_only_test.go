package http

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

type httpEvidenceWriter struct {
	netio.AuditRecordWriter
	records []*types.HTTP
}

func (w *httpEvidenceWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.HTTP))
	return nil
}

func TestRequestOnlyEvidence(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{IncludePayloads: true}
	for _, body := range []string{"payload", "part"} {
		wire := []byte("POST /submit HTTP/1.1\r\nHost: c2.example\r\nContent-Length: 7\r\nContent-Type: application/octet-stream\r\n\r\n" + body)
		if !Decoder.CanDecode(wire, nil) {
			t.Fatal("unanswered request not selected")
		}
		for split := 1; split < len(wire); split++ {
			w := &httpEvidenceWriter{}
			Decoder.Writer = w
			c := &core.ConversationInfo{Ident: "flow", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 1234, ServerPort: 8081}
			c.Data = core.DataFragments{
				&core.StreamData{RawData: wire[:split], CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(10, 0)}},
				&core.StreamData{RawData: wire[split:], CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(11, 0)}},
			}
			(&httpReader{conversation: c}).Decode()
			if len(w.records) != 1 {
				t.Fatalf("split %d: %v", split, w.records)
			}
			r := w.records[0]
			if body == "part" && r.ReassemblyStatus == "" {
				t.Fatal("truncated request body not qualified")
			}
			if r.Method != "POST" || r.Host != "c2.example" || r.URL != "/submit" || string(r.RequestBody) != body || r.Timestamp != time.Unix(10, 0).UnixNano() || r.SrcIP != c.ClientIP {
				t.Fatalf("split %d: %v", split, r)
			}
		}
	}
	for _, bad := range []string{"binary POST / HTTP/1.1\r\n", "POSTscript / HTTP/1.1\r\n", "GET / NOTHTTP\r\n", "GET / HTTP/1.1 garbage\r\n"} {
		if Decoder.CanDecode([]byte(bad), nil) {
			t.Fatalf("claimed %q", bad)
		}
	}
}

func TestInterimResponseDoesNotConsumeRequest(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	c := &core.ConversationInfo{Ident: "flow", Data: core.DataFragments{
		&core.StreamData{RawData: []byte("POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n")},
		&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")},
	}}
	(&httpReader{conversation: c}).Decode()
	if len(w.records) != 2 || w.records[0].Method != "POST" || w.records[1].Method != "POST" {
		t.Fatalf("pairing: %v", w.records)
	}
}

// A response whose request was not captured has empty request fields;
// request-side rules (Empty User Agent, Unusual HTTP Method) matched it.
func TestUnpairedRecordsSayWhichHalfIsMissing(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	has := func(r *types.HTTP, q string) bool {
		for _, v := range r.ParseQualifications {
			if v == q {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		name string
		data core.DataFragments
		want string
	}{
		{"response only", core.DataFragments{&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("HTTP/1.1 204 No Content\r\n\r\n")}}, ResponseWithoutRequest},
		{"request only", core.DataFragments{&core.StreamData{RawData: []byte("GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n")}}, RequestWithoutResponse},
		{"paired", core.DataFragments{
			&core.StreamData{RawData: []byte("GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n")},
			&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("HTTP/1.1 204 No Content\r\n\r\n")},
		}, ""},
	} {
		w := &httpEvidenceWriter{}
		Decoder.Writer = w
		(&httpReader{conversation: &core.ConversationInfo{Ident: "flow", Data: tc.data}}).Decode()
		if len(w.records) != 1 {
			t.Fatalf("%s: %d records", tc.name, len(w.records))
		}
		r := w.records[0]
		if tc.want != "" && !has(r, tc.want) || has(r, ResponseWithoutRequest) && tc.want != ResponseWithoutRequest || has(r, RequestWithoutResponse) && tc.want != RequestWithoutResponse {
			t.Fatalf("%s: %v", tc.name, r.ParseQualifications)
		}
	}
}
