package flow

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

const rotationSecond = int64(time.Second)

func rotationFixture(port int) (connections []*types.Connection, packets []*types.TCP) {
	for n := range 6 {
		row := &types.Connection{ObservationID: fmt.Sprint(n), CounterSemantics: "tuple-cumulative", SnapshotSequence: 1,
			TransportProto: "TCP", NetworkScope: "interface-1/vlan-7", SrcIP: "10.0.0.2", SrcPort: "48000", DstIP: fmt.Sprintf("16.0.0.%d", n+1),
			DstPort: fmt.Sprint(port), TimestampFirst: (100 + int64(n)*2) * rotationSecond, TimestampLast: (101 + int64(n)*2) * rotationSecond,
			CommunityID: fmt.Sprintf("1:peer-%d", n), NumSYNFlags: 1, PacketsClientToServer: 1, TCPInitiatorObserved: true}
		if n == 5 {
			row.AppPayloadSize64, row.PacketsServerToClient, row.Established = 38, 2, true
			packets = []*types.TCP{
				{Timestamp: row.TimestampFirst + 2, SrcIP: row.DstIP, DstIP: row.SrcIP, SrcPort: int32(port), DstPort: 48000, CommunityID: row.CommunityID, PayloadSize: 20},
				{Timestamp: row.TimestampFirst + 1, SrcIP: row.SrcIP, DstIP: row.DstIP, SrcPort: 48000, DstPort: int32(port), CommunityID: row.CommunityID, PayloadSize: 18},
			}
		}
		connections = append(connections, row)
	}
	return connections, packets
}

func TestPeerRotationRequiresDistinctPeersAndDirectionalEvidence(t *testing.T) {
	for _, name := range []string{"observed", "ordinary browsing", "mail retries outside window", "service failover", "one-way payload", "same peer", "repeat attempts", "other scope", "other port", "superseded failure", "reused tuple"} {
		t.Run(name, func(t *testing.T) {
			port := 8080
			if name == "mail retries outside window" {
				port = 25
			}
			rows, packets := rotationFixture(port)
			want := 0
			switch name {
			case "observed", "service failover":
				want = 1
				// A real failover matching the pattern is also a hunt candidate.
				repeat := *rows[0]
				repeat.SnapshotSequence++
				rows = append(rows, &repeat)
				if name == "service failover" {
					other := *rows[5]
					other.ObservationID, other.DstIP, other.CommunityID = "next", "16.0.0.7", "1:next"
					other.TimestampFirst, other.TimestampLast = other.TimestampFirst+rotationSecond, other.TimestampLast+rotationSecond
					rows = append(rows, &other)
					server, client := *packets[0], *packets[1]
					server.SrcIP, client.DstIP = other.DstIP, other.DstIP
					server.CommunityID, client.CommunityID = other.CommunityID, other.CommunityID
					server.Timestamp, client.Timestamp = server.Timestamp+rotationSecond, client.Timestamp+rotationSecond
					packets = append(packets, &server, &client)
				}
			case "ordinary browsing":
				for _, row := range rows[:5] {
					row.Established, row.AppPayloadSize64 = true, 256
				}
			case "mail retries outside window":
				rows[0].TimestampFirst, rows[0].TimestampLast = rotationSecond, 2*rotationSecond
				rows[5].TimestampFirst += 250 * rotationSecond
				rows[5].TimestampLast += 250 * rotationSecond
				for _, p := range packets {
					p.Timestamp += 250 * rotationSecond
				}
			case "one-way payload":
				packets = packets[1:]
			case "same peer":
				rows[5].DstIP, rows[5].SrcPort = rows[0].DstIP, "48001"
				packets[0].SrcIP, packets[0].DstPort = rows[0].DstIP, 48001
				packets[1].DstIP, packets[1].SrcPort = rows[0].DstIP, 48001
			case "repeat attempts":
				rows[0].DstIP = rows[1].DstIP
			case "other scope":
				rows[0].NetworkScope = "interface-1/vlan-8"
			case "other port":
				rows[0].DstPort = "443"
			case "superseded failure":
				latest := *rows[0]
				latest.SnapshotSequence++
				latest.Established, latest.AppPayloadSize64 = true, 32
				rows = append(rows, &latest)
			case "reused tuple":
				other := *rows[5]
				other.ObservationID, other.NetworkScope = "other", "interface-2/vlan-7"
				rows = append(rows, &other)
			}
			var index rotationIndex
			for ordinal, row := range rows {
				if err := index.add(row, ordinal); err != nil {
					t.Fatal(err)
				}
			}
			failures, witnesses := index.prepare()
			for ordinal, packet := range packets {
				index.observePayload(witnesses, packet, ordinal)
			}
			got, err := index.candidates(t.Context(), failures, witnesses)
			if err != nil || len(got) != want {
				t.Fatalf("got %+v (%v), want %d candidates", got, err, want)
			}
			if want == 1 && (got[0].FailedPeersTotal != 5 || got[0].FailedPeers[4].Ordinal != 6 || got[0].PayloadOrdinals != [2]int{1, 0}) {
				t.Fatalf("incorrect evidence references: %+v", got[0])
			}
		})
	}
}

func TestReadPeerRotationRequiresFinalizedBoundTracks(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadPeerRotation(t.Context(), dir); err == nil {
		t.Fatal("an unfinished capture was accepted")
	}
	capture, err := evidence.NewCapture(t.Context(), dir, evidence.CaptureConfig{Kind: "live", Source: "peer fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Close("complete", 1, 0, nil); err != nil {
		t.Fatal(err)
	}
	connections, packets := rotationFixture(8080)
	stages := []evidence.AuditStage{}
	for _, track := range []struct {
		name string
		typ  types.Type
		rows []proto.Message
	}{{"Connection", types.Type_NC_Connection, nil}, {"TCP", types.Type_NC_TCP, nil}} {
		if track.name == "Connection" {
			for _, row := range connections {
				track.rows = append(track.rows, row)
			}
		} else {
			for _, row := range packets {
				track.rows = append(track.rows, row)
			}
		}
		name := track.name + ".ncap.gz"
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		w := delimited.NewWriter(gz)
		for _, row := range append([]proto.Message{&types.Header{Type: track.typ}}, track.rows...) {
			if err := w.PutProto(row); err != nil {
				t.Fatal(err)
			}
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		stages = append(stages, evidence.AuditStage{Type: track.name, Stage: "packet", State: "sealed", Coverage: "complete", Records: int64(len(track.rows)), Files: []evidence.SealedAuditFile{{Name: name}}})
	}
	if err := capture.SealAuditStages(stages); err != nil {
		t.Fatal(err)
	}
	if err := capture.MarkAuditOutputReady(); err != nil {
		t.Fatal(err)
	}
	result, err := ReadPeerRotation(t.Context(), dir)
	if err != nil || result.AuditGeneration == "" || len(result.Candidates) != 1 {
		t.Fatalf("finalized tracks: %+v (%v)", result, err)
	}
	if err := os.Truncate(filepath.Join(dir, "TCP.ncap.gz"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPeerRotation(t.Context(), dir); err == nil || !strings.Contains(err.Error(), "TCP audit") {
		t.Fatalf("mutated TCP stage was not refused: %v", err)
	}
}
