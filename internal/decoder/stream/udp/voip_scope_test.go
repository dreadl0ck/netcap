package udp

import (
	"fmt"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/rtp"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
)

type voipScopeWriter struct {
	netio.AuditRecordWriter
	records []proto.Message
}

func (w *voipScopeWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m))
	return nil
}

func TestScopedUDPSignalingAndMedia(t *testing.T) {
	oldConfig, oldMedia := decoderconfig.Instance, sipaudit.Media
	oldRTP, oldDTMF := rtp.Decoder.Writer, rtp.EventDecoder.Writer
	oldCount, oldEvents := rtp.Decoder.NumRecordsWritten, rtp.EventDecoder.NumRecordsWritten
	t.Cleanup(func() {
		decoderconfig.Instance, sipaudit.Media = oldConfig, oldMedia
		rtp.Decoder.Writer, rtp.EventDecoder.Writer = oldRTP, oldDTMF
		rtp.Decoder.NumRecordsWritten, rtp.EventDecoder.NumRecordsWritten = oldCount, oldEvents
	})
	decoderconfig.Instance = decoderconfig.DefaultConfig.Clone()
	for _, peer := range []struct {
		iface int
		vni   uint32
	}{{2, 7}, {1, 8}} {
		t.Run(fmt.Sprintf("interface=%d/vni=%d", peer.iface, peer.vni), func(t *testing.T) {
			sipaudit.Media = sipaudit.NewAssociations()
			w := &voipScopeWriter{}
			rtp.Decoder.Writer, rtp.EventDecoder.Writer = w, w
			processor := packetview.New(packetview.Limits{})
			var ordinal uint64
			packet := func(iface int, vni uint32, reverse bool, sp, dp layers.UDPPort, data []byte) gopacket.Packet {
				ordinal++
				ip := testutil.IP(false, reverse, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: sp, DstPort: dp}, gopacket.Payload(data)))
				p := testutil.Packet(testutil.Ethernet(testutil.Tunnel("vxlan", vni, ip)), iface, ordinal)
				p.Metadata().Timestamp = time.Unix(int64(ordinal), 0)
				r := processor.Process(p, ordinal)
				if r.Packet == nil {
					t.Fatalf("normalization: %s", r.Status)
				}
				return r.Packet
			}
			observe := func(iface int, vni uint32, answer bool, encoding string) {
				start, ip, port := "INVITE sip:b@example.test SIP/2.0", "10.0.0.1", 4000
				if answer {
					start, ip, port = "SIP/2.0 200 OK", "10.0.0.2", 5000
				}
				body := fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 110\r\na=rtpmap:110 %s/8000\r\n", ip, port, encoding)
				wire := fmt.Sprintf("%s\r\nFrom: <sip:a@example.test>;tag=one\r\nCall-ID: same-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", start, len(body), body)
				p := packet(iface, vni, answer, 5060, 5060, []byte(wire))
				pool := newUDPStreamPool()
				pool.HandleUDP(p, p.TransportLayer())
			}
			observe(1, 7, false, "telephone-event")
			observe(1, 7, true, "telephone-event")
			mediaPool := newUDPStreamPool()
			media := []byte{0x80, 110, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 5, 0x8a, 0, 160}
			for _, loc := range []struct {
				iface int
				vni   uint32
			}{{1, 7}, peer} {
				p := packet(loc.iface, loc.vni, false, 4000, 5000, media)
				mediaPool.HandleUDP(p, p.TransportLayer())
			}
			if len(mediaPool.streams) != 2 {
				t.Fatal("fixture merged scoped UDP streams")
			}
			for _, u := range mediaPool.streams {
				u.decode()
			}
			if len(w.records) != 2 {
				t.Fatalf("cross-scope RTP/DTMF emission: %v", w.records)
			}
			m, ok := w.records[0].(*types.RTP)
			if !ok || m.CallID != "same-call" || m.Encoding != "telephone-event" {
				t.Fatalf("same-scope RTP: %v", w.records)
			}
			e, ok := w.records[1].(*types.DTMF)
			if !ok || e.CallID != "same-call" || e.Digit != "5" {
				t.Fatalf("same-scope DTMF: %v", w.records)
			}

			// Identical dialog identifiers and payload type may negotiate a different codec.
			observe(peer.iface, peer.vni, false, "pcma")
			observe(peer.iface, peer.vni, true, "pcma")
			w.records = nil
			p := packet(peer.iface, peer.vni, false, 4000, 5000, media)
			pool := newUDPStreamPool()
			pool.HandleUDP(p, p.TransportLayer())
			for _, u := range pool.streams {
				u.decode()
			}
			if len(w.records) != 1 {
				t.Fatalf("peer inherited DTMF codec: %v", w.records)
			}
			if m := w.records[0].(*types.RTP); m.Encoding != "pcma" || m.CallID != "same-call" {
				t.Fatalf("peer codec: %v", m)
			}
		})
	}
}
