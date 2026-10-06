package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestBehaviorRecordsRetainedSourceAndImmutableAlert(t *testing.T) {
	s := behaviorServerFixture(t)
	at := time.Unix(1700000000, 0).UnixNano()
	fact := behavior.Fact{Kind: "service", Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Port: 445, Token: "43210:123"}
	evidence, _ := json.Marshal(behavior.Evidence{Detector: "lateral.smb-fanout", Observed: fact, WindowNS: int64(time.Minute)})
	alert := &types.Alert{Timestamp: at, RuleName: "lateral.smb-fanout", RecordType: "Behavior", MatchedRecord: string(evidence)}
	sink, err := rules.NewFileAlertWriter(s.outDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteAlert(alert); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.outDir, "Alert.ncap.gz"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, kind types.Type, records ...proto.Message) {
		t.Helper()
		var buf bytes.Buffer
		writer := delimited.NewWriter(&buf)
		if err := writer.PutProto(&types.Header{Type: kind}); err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if err := writer.PutProto(record); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(s.outDir, name+".ncap"), buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("Connection", types.Type_NC_Connection, &types.Connection{TimestampFirst: at, TimestampLast: at + int64(5*time.Minute), TransportProto: "TCP", SrcIP: fact.SrcIP, DstIP: fact.DstIP, SrcPort: "43210", DstPort: "445", NumRSTFlags: 1})
	write("SMB", types.Type_NC_SMB, &types.SMB{Timestamp: at + 1, SrcIP: fact.SrcIP, DstIP: fact.DstIP, SrcPort: 43210, DstPort: 445, AuthStatus: "IN_PROGRESS"})
	target := "/api/behavior/records?alertId=" + url.QueryEscape(alertResponse(alert).AlertID)
	response := httptest.NewRecorder()
	s.handleBehaviorRecords(response, httptest.NewRequest(http.MethodGet, target, nil))
	var data behaviorRecordsResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &data) != nil || len(data.Records) != 2 || len(data.Unavailable) != 0 || data.Records[0].CaptureLagNS != int64(5*time.Minute) || data.Records[1].Authentication != "IN_PROGRESS" {
		t.Fatalf("source context: %d %s", response.Code, response.Body)
	}
	after, _ := os.ReadFile(filepath.Join(s.outDir, "Alert.ncap.gz"))
	if !bytes.Equal(before, after) {
		t.Fatal("drill-down rewrote immutable early alert")
	}
	for _, target := range []string{target + "&inputFile=unknown", target + "&sessionId=unknown"} {
		response = httptest.NewRecorder()
		s.handleBehaviorRecords(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusNotFound {
			t.Fatal("invalid selector fell back to current capture")
		}
	}
	if err := os.Remove(filepath.Join(s.outDir, "SMB.ncap")); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.handleBehaviorRecords(response, httptest.NewRequest(http.MethodGet, target, nil))
	if json.Unmarshal(response.Body.Bytes(), &data) != nil || len(data.Unavailable) != 1 {
		t.Fatal("absent SMB evidence was not disclosed")
	}
	records := make([]proto.Message, 65)
	for i := range records {
		records[i] = &types.SMB{Timestamp: at + int64(i), SrcIP: fact.SrcIP, DstIP: fact.DstIP, SrcPort: 43210, DstPort: 445}
	}
	write("SMB", types.Type_NC_SMB, records...)
	response = httptest.NewRecorder()
	s.handleBehaviorRecords(response, httptest.NewRequest(http.MethodGet, target, nil))
	if json.Unmarshal(response.Body.Bytes(), &data) != nil || len(data.Records) != 64 || !data.Truncated {
		t.Fatalf("display bound not enforced: %s", response.Body)
	}
	write("SMB", types.Type_NC_Connection)
	response = httptest.NewRecorder()
	s.handleBehaviorRecords(response, httptest.NewRequest(http.MethodGet, target, nil))
	if json.Unmarshal(response.Body.Bytes(), &data) != nil || len(data.Unavailable) != 1 {
		t.Fatal("wrong audit type accepted")
	}
}
