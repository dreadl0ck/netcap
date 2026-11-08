package webui

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestSoftwareHostAssessmentOccurrences(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, []proto.Message{
		&types.Software{Product: "server", Vendor: "one", Version: "1", Timestamp: 1700000000000000001, ObservedHost: "192.0.2.1", ObservationRole: "server", VulnerabilityAssessment: "unavailable"},
		&types.Software{Product: "server", Vendor: "one", Version: "1", Timestamp: 1700000000000000002, ObservedHost: "192.0.2.2", ObservationRole: "client"},
		&types.Software{Product: "server", Vendor: "two", Version: "1", Timestamp: 1700000000000000003},
	})
	rows, err := readSoftware(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Count != 2 {
		t.Fatalf("vendor identity collapsed: %+v", rows)
	}
	obs := rows[0].Observations
	if len(obs) != 2 || obs[0].Host != "192.0.2.1" || obs[1].Host != "192.0.2.2" || obs[1].VulnerabilityAssessment != "unavailable" || obs[0].TimestampNs != "1700000000000000001" {
		t.Fatalf("lost occurrence evidence: %+v", obs)
	}
}

func TestSoftwareObservationCapIsExplicit(t *testing.T) {
	for _, count := range []int{1024, 1025} {
		dir := t.TempDir()
		rows := make([]proto.Message, count)
		for i := range rows {
			rows[i] = &types.Software{Product: "same", Timestamp: int64(i + 1)}
		}
		writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, rows)
		result, err := readSoftware(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 1 || result[0].Count != count || len(result[0].Observations) != 1024 || result[0].ObservationsCapped != (count > 1024) {
			t.Fatalf("count %d: %+v", count, result)
		}
	}
}
