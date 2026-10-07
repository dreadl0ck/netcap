package packet

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestConnectionRepeatedReverseSnapshots(t *testing.T) {
	connectionConcurrencySetup(t)
	first := connectionBenchmarkPackets(t, 1)[0]
	first.TransportLayer().(*layers.TCP).Window = 100
	first = serializedEvidencePacket(t, first, first.Metadata().Timestamp)
	handlePacket(first)
	reverse := gopacket.NewPacket(first.Data(), layers.LayerTypeEthernet, gopacket.Default)
	reverse.Metadata().CaptureInfo = first.Metadata().CaptureInfo
	reverse.Metadata().Timestamp = first.Metadata().Timestamp.Add(-time.Second)
	ip, tcp := reverse.NetworkLayer().(*layers.IPv4), reverse.TransportLayer().(*layers.TCP)
	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
	tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	tcp.Window = 300
	tcp.Payload = append(tcp.Payload, make([]byte, 20)...)
	reverse = serializedEvidencePacket(t, reverse, reverse.Metadata().Timestamp)
	handlePacket(reverse)
	w := &connectionTestWriter{}
	d := &Decoder{Writer: w}
	for range 3 {
		connectionDecoder.FlushState(d)
	}
	for i, record := range w.records {
		if record.SrcIP != ip.SrcIP.String() || record.BytesClientToServer != int64(reverse.Metadata().Length) ||
			record.BytesServerToClient != int64(first.Metadata().Length) || record.MeanWindowSize != 200 {
			t.Fatalf("snapshot %d has incorrect direction/mean: %s", i, record)
		}
		expected := proto.Clone(w.records[0]).(*types.Connection)
		expected.SnapshotSequence = uint64(i + 1)
		if !proto.Equal(record, expected) {
			t.Fatalf("snapshot %d changed without incoming traffic", i)
		}
	}
	handlePacket(first)
	connectionDecoder.FlushState(d)
	last := w.records[len(w.records)-1]
	if last.BytesClientToServer != int64(reverse.Metadata().Length) || last.BytesServerToClient != 2*int64(first.Metadata().Length) || last.MeanWindowSize != 166 {
		t.Fatalf("flush changed subsequent accounting: %s", last)
	}
}

func TestConnectionWideCountersAndSnapshotIdentity(t *testing.T) {
	connectionConcurrencySetup(t)
	p := connectionBenchmarkPackets(t, 1)[0]
	handlePacket(p)
	for _, c := range conns.Items {
		c.TotalSize64, c.AppPayloadSize64, c.NumPackets64 = math.MaxInt32-1, math.MaxInt32-1, math.MaxInt32-1
		c.BytesClientToServer, c.packetsClientToServer = c.TotalSize64, c.NumPackets64
		c.NumACKFlags = math.MaxInt32
	}
	handlePacket(p)
	handlePacket(p)
	w := &connectionTestWriter{}
	d := &Decoder{Writer: w}
	connectionDecoder.FlushState(d)
	connectionDecoder.FlushState(d)
	first, last := w.records[0], w.records[1]
	if first.TotalSize64 != int64(math.MaxInt32-1)+2*int64(p.Metadata().Length) || first.NumPackets64 != int64(math.MaxInt32)+1 ||
		first.AppPayloadSize64 != int64(math.MaxInt32-1)+2*int64(len(p.TransportLayer().LayerPayload())) || !first.LegacyCountersSaturated ||
		first.TotalSize != math.MaxInt32 || first.NumPackets != math.MaxInt32 || first.AppPayloadSize != math.MaxInt32 || first.NumACKFlags != math.MaxInt32 {
		t.Fatalf("overflowed/lost exact counts: %s", first)
	}
	if first.ObservationID == "" || first.ObservationID != last.ObservationID || first.CounterSemantics != "tuple-cumulative" || first.SnapshotSequence != 1 || last.SnapshotSequence != 2 {
		t.Fatalf("snapshot identity: %s / %s", first, last)
	}
}

func TestConnectionWindowMeanIncludesZeroAndIsOrderIndependent(t *testing.T) {
	connectionConcurrencySetup(t)
	for _, windows := range [][]uint16{{0, 101, 202, 0}, {202, 0, 0, 101}} {
		ResetConnections()
		base := connectionBenchmarkPackets(t, 1)[0]
		for _, window := range windows {
			p := gopacket.NewPacket(base.Data(), layers.LayerTypeEthernet, gopacket.Default)
			p.Metadata().CaptureInfo = base.Metadata().CaptureInfo
			p.TransportLayer().(*layers.TCP).Window = window
			handlePacket(p)
		}
		for _, c := range conns.Items {
			if c.MeanWindowSize != 75 {
				t.Fatalf("windows %v: mean=%d, want floor(303/4)=75", windows, c.MeanWindowSize)
			}
		}
	}
}

func TestConnectionSameAddressDirections(t *testing.T) {
	connectionConcurrencySetup(t)
	first := connectionBenchmarkPackets(t, 1)[0]
	ip := first.NetworkLayer().(*layers.IPv4)
	ip.DstIP = ip.SrcIP
	first = serializedEvidencePacket(t, first, first.Metadata().Timestamp)
	handlePacket(first)
	reverse := gopacket.NewPacket(first.Data(), layers.LayerTypeEthernet, gopacket.Default)
	reverse.Metadata().CaptureInfo = first.Metadata().CaptureInfo
	ip2 := reverse.NetworkLayer().(*layers.IPv4)
	ip2.SrcIP, ip2.DstIP = ip2.DstIP, ip2.SrcIP
	tcp := reverse.TransportLayer().(*layers.TCP)
	tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	reverse = serializedEvidencePacket(t, reverse, first.Metadata().Timestamp.Add(-time.Second))
	handlePacket(reverse)
	w := &connectionTestWriter{}
	connectionDecoder.FlushState(&Decoder{Writer: w})
	if len(w.records) != 1 {
		t.Fatalf("connections=%d", len(w.records))
	}
	got := w.records[0]
	if got.SrcPort != strconv.Itoa(int(tcp.SrcPort)) || got.BytesClientToServer != int64(reverse.Metadata().Length) || got.BytesServerToClient != int64(first.Metadata().Length) || got.PacketsClientToServer != 1 || got.PacketsServerToClient != 1 {
		t.Fatalf("same-address endpoints lost direction: %s", got)
	}
}

func serializedEvidencePacket(t *testing.T, packet gopacket.Packet, timestamp time.Time) gopacket.Packet {
	t.Helper()
	tcp := packet.TransportLayer().(*layers.TCP)
	ip := packet.NetworkLayer().(*layers.IPv4)
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packet.LinkLayer().(*layers.Ethernet), ip, tcp, gopacket.Payload(tcp.Payload)); err != nil {
		t.Fatal(err)
	}
	out := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	if layer := out.ErrorLayer(); layer != nil {
		t.Fatal(layer.Error())
	}
	out.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	return out
}

func TestConnectionTupleReuseAndLatePriorPacket(t *testing.T) {
	connectionConcurrencySetup(t)
	base := connectionBenchmarkPackets(t, 1)[0]
	tcp := base.TransportLayer().(*layers.TCP)
	tcp.SYN, tcp.ACK, tcp.PSH = true, false, false
	tcp.Seq = 100
	tcp.Payload = nil
	first := serializedEvidencePacket(t, base, base.Metadata().Timestamp)
	handlePacket(first)
	tcp.SYN, tcp.ACK, tcp.RST = false, true, true
	reset := serializedEvidencePacket(t, base, first.Metadata().Timestamp.Add(time.Millisecond))
	handlePacket(reset)
	tcp.SYN, tcp.ACK, tcp.RST = true, false, false
	tcp.Seq = 200
	next := serializedEvidencePacket(t, base, first.Metadata().Timestamp.Add(2*time.Millisecond))
	handlePacket(next)
	tcp.SYN, tcp.ACK = false, true
	current := serializedEvidencePacket(t, base, first.Metadata().Timestamp.Add(3*time.Millisecond))
	handlePacket(current)
	late := serializedEvidencePacket(t, base, first.Metadata().Timestamp.Add(500*time.Microsecond))
	handlePacket(late)
	w := &connectionTestWriter{}
	connectionDecoder.FlushState(&Decoder{Writer: w})
	if len(w.records) != 2 {
		t.Fatalf("reused tuple produced %d observations, want 2", len(w.records))
	}
	var previous, newer *types.Connection
	for _, c := range w.records {
		if c.TimestampFirst == first.Metadata().Timestamp.UnixNano() {
			previous = c
		} else {
			newer = c
		}
	}
	if previous == nil || newer == nil || previous.NumPackets64 != 3 || newer.NumPackets64 != 2 || previous.ObservationID == newer.ObservationID || previous.TimestampLast != reset.Metadata().Timestamp.UnixNano() || newer.TimestampFirst != next.Metadata().Timestamp.UnixNano() {
		t.Fatalf("session boundary/late attribution lost: %v", w.records)
	}
}
