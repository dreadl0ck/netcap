package tcp

import (
	"fmt"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/sip"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
)

func TestTCPConversationCarriesSIPScope(t *testing.T) {
	w := round2Config(t, sip.Decoder)
	decoderconfig.Instance.Quiet = true
	decoderconfig.Instance.Checksum = false
	old := sipaudit.Media
	sipaudit.Media = sipaudit.NewAssociations()
	t.Cleanup(func() { sipaudit.Media = old })
	factory := newStreamFactory()
	assembler := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
	processor := packetview.New(packetview.Limits{})
	var ordinal uint64
	scopes := map[string]string{}
	for _, loc := range []struct {
		iface int
		vni   uint32
		codec string
	}{{1, 7, "telephone-event"}, {2, 7, "pcma"}, {1, 8, "pcmu"}} {
		send := func(reverse bool, seq, ack uint32, flags, payload string) {
			ordinal++
			wire := testutil.Ethernet(testutil.Tunnel("vxlan", loc.vni, testutil.TCP(false, reverse, seq, ack, flags, payload)))
			p := testutil.Packet(wire, loc.iface, ordinal)
			p.Metadata().Timestamp = time.Unix(int64(ordinal), 0)
			r := processor.Process(p, ordinal)
			if r.Packet == nil {
				t.Fatalf("normalization: %s", r.Status)
			}
			scopes[packetview.Scope(r.Packet)] = loc.codec
			ReassemblePacket(r.Packet, assembler)
		}
		send(false, 100, 0, "S", "")
		send(true, 200, 101, "SA", "")
		for _, answer := range []bool{false, true} {
			start, ip, port := "INVITE sip:b@example.test SIP/2.0", "10.0.0.1", 4000
			if answer {
				start, ip, port = "SIP/2.0 200 OK", "10.0.0.2", 5000
			}
			body := fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 110\r\na=rtpmap:110 %s/8000\r\n", ip, port, loc.codec)
			msg := fmt.Sprintf("%s\r\nFrom: <sip:a@example.test>;tag=one\r\nCall-ID: same-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", start, len(body), body)
			if answer {
				send(true, 201, 101, "A", msg)
			} else {
				send(false, 101, 201, "A", msg)
			}
		}
	}
	assembler.FlushAll()
	factory.wg.Wait()
	if len(w.records) != 6 || len(scopes) != 3 {
		t.Fatalf("records=%d scopes=%v", len(w.records), scopes)
	}
	counts := map[string]int{}
	for _, record := range w.records {
		s := record.(*types.SIP)
		if _, ok := scopes[s.NetworkScope]; !ok || s.Transport != "TCP" || len(s.Body) != 0 {
			t.Fatalf("lost scope/transport or payload policy: %v", s)
		}
		counts[s.NetworkScope]++
	}
	for scope, want := range scopes {
		id, codec, ok := sipaudit.Media.Lookup(scope, "10.0.0.1", "10.0.0.2", 4000, 5000, 110, time.Unix(20, 0).UnixNano())
		if counts[scope] != 2 || !ok || id != "same-call" || codec.Encoding != want {
			t.Fatalf("scope=%q records=%d id=%q codec=%+v ok=%v", scope, counts[scope], id, codec, ok)
		}
	}
	if _, _, ok := sipaudit.Media.Lookup("if:99", "10.0.0.1", "10.0.0.2", 4000, 5000, 110, time.Unix(20, 0).UnixNano()); ok {
		t.Fatal("TCP signaling escaped capture scope")
	}
}
