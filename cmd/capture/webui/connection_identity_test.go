package webui

import (
	"net/url"
	"strings"
	"testing"
)

func TestConnectionObservationSelectionSeparatesSnapshotsAndTupleReuse(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	rows := []ConnectionSummary{{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", CommunityID: "same", ObservationID: a, SnapshotSequence: 1}, {SrcIP: "192.0.2.1", DstIP: "192.0.2.2", CommunityID: "same", ObservationID: a, SnapshotSequence: 2}, {SrcIP: "192.0.2.1", DstIP: "192.0.2.2", CommunityID: "same", ObservationID: b, SnapshotSequence: 1}}
	filter, err := parseConnectionFilter(url.Values{"observationId": {a}, "snapshotSequence": {"2"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []*connectionSnapshot{newConnectionSnapshot(rows), {rows: rows}} {
		result := snapshot.selectRows(filter)
		if result.TotalCount != 1 || result.Connections[0].ObservationID != a || result.Connections[0].SnapshotSequence != 2 {
			t.Fatalf("exact selection changed: %+v", result)
		}
	}
	for _, q := range []url.Values{{"observationId": {a}}, {"observationId": {a}, "snapshotSequence": {"0"}}, {"observationId": {a, b}, "snapshotSequence": {"1"}}} {
		if _, err := parseConnectionFilter(q); err == nil {
			t.Fatal("ambiguous identity accepted")
		}
	}
}
