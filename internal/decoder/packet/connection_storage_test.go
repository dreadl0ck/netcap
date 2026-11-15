package packet

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestSpilledConnectionsMatchMemoryAcrossEvictionAndTupleReuse(t *testing.T) {
	connectionConcurrencySetup(t)
	packets := connectionBenchmarkPackets(t, 300)
	base := connectionBenchmarkPackets(t, 1)[0]
	tcp := base.TransportLayer().(*layers.TCP)
	tcp.SYN, tcp.ACK, tcp.PSH = true, false, false
	tcp.Payload = nil
	tcp.Seq = 100
	start := base.Metadata().Timestamp
	first := serializedEvidencePacket(t, base, start)
	tcp.SYN, tcp.ACK, tcp.RST = false, true, true
	reset := serializedEvidencePacket(t, base, start.Add(time.Millisecond))
	tcp.SYN, tcp.ACK, tcp.RST = true, false, false
	tcp.Seq = 200
	next := serializedEvidencePacket(t, base, start.Add(2*time.Millisecond))
	tcp.SYN, tcp.ACK = false, true
	current := serializedEvidencePacket(t, base, start.Add(3*time.Millisecond))
	late := serializedEvidencePacket(t, base, start.Add(500*time.Microsecond))
	tooEarly := serializedEvidencePacket(t, base, start.Add(-time.Millisecond))
	sequence := []gopacket.Packet{first, reset, next, current, late, tooEarly}
	// Churn must evict the reused tuple, then revisit both of its generations.
	sequence = append(sequence, packets[1:]...)
	sequence = append(sequence, late, current)
	run := func(store *aggregate.Store) []*types.Connection {
		conf.AggregateStore = nil
		ResetConnections()
		conf.AggregateStore = store
		w := &connectionTestWriter{}
		d := &Decoder{Writer: w}
		for _, p := range sequence {
			handlePacket(p)
		}
		if got := connectionDecoder.FlushState(d); got != 301 {
			t.Fatalf("snapshot count=%d, want 301", got)
		}
		for _, p := range sequence {
			handlePacket(p)
		}
		if err := connectionDecoder.DeInit(d); err != nil {
			t.Fatal(err)
		}
		sort.Slice(w.records, func(i, j int) bool {
			a, b := w.records[i], w.records[j]
			if a.ObservationID != b.ObservationID {
				return a.ObservationID < b.ObservationID
			}
			return a.SnapshotSequence < b.SnapshotSequence
		})
		return w.records
	}
	want := run(nil)
	for _, limit := range []int64{1, 2048, 1 << 20} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			store, err := aggregate.Open(t.TempDir(), limit, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			defer func() { conf.AggregateStore = nil }()
			got := run(store)
			if len(got) != len(want) {
				t.Fatalf("records=%d, want %d", len(got), len(want))
			}
			for i := range got {
				if !proto.Equal(got[i], want[i]) {
					t.Fatalf("spilled record %d differs\ngot: %s\nwant: %s", i, got[i], want[i])
				}
			}
			if h := store.Health(); h.PeakBytes > limit || h.DiskWrites == 0 {
				t.Fatal(h)
			}
			ResetConnections()
			if conns.Size() != 0 {
				t.Fatal("ResetConnections retained disk-backed observations")
			}
		})
	}
}

func TestConnectionStorageRejectsTruncatedOrTrailingState(t *testing.T) {
	connectionConcurrencySetup(t)
	p := connectionBenchmarkPackets(t, 1)[0]
	id := connectionID{Tuple: "test", IPProtocol: 6}
	c := makeConnection(p, id, p.LinkLayer(), p.NetworkLayer(), p.TransportLayer(), 9)
	c.applications = map[string]struct{}{"TLS": {}, "HTTP": {}}
	c.sni = "example.test"
	c.finClient, c.finServer, c.archived, c.tcpClosed = true, true, true, true
	c.endedAt = c.startedAt + 1
	wire, err := marshalConnection(c)
	if err != nil {
		t.Fatal(err)
	}
	other, err := unmarshalConnection(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire2, err := marshalConnection(other)
	if err != nil || string(wire2) != string(wire) {
		t.Fatal("runtime state did not round trip", err)
	}
	for i := 0; i < len(wire); i++ {
		if _, err = unmarshalConnection(wire[:i]); err == nil {
			t.Fatalf("truncated state accepted at %d", i)
		}
	}
	if _, err = unmarshalConnection(append(wire, 0)); err == nil {
		t.Fatal("trailing state accepted")
	}
}
