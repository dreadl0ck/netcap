package tls

import (
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func TestTLSHelloTransportBoundary(t *testing.T) {
	h, records := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0xc0, 0x2f, 1, 0, 0, 0)
	message := append([]byte{1, 0, 0, byte(len(body))}, body...)
	for _, reason := range []string{"after-rst", "after-fin"} {
		// Both record framing and handshake framing across complete records
		// must stop at the transport boundary.
		for _, recordSplit := range []bool{false, true} {
			for cut := 1; cut < len(message); cut++ {
				w := &helloWriter{}
				ClientHelloDecoder.Writer = w
				records.records = nil
				wire := recordWire(22, message)
				a, b := wire[:cut], wire[cut:]
				if recordSplit {
					a, b = recordWire(22, message[:cut]), recordWire(22, message[cut:])
				}
				h.conversation.Data = core.DataFragments{
					&core.StreamData{RawData: a, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}},
					&core.StreamData{RawData: b, TCPObservation: reason, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(2, 0)}},
				}
				h.Decode()
				if len(w.messages) != 0 {
					t.Fatalf("%s recordSplit=%v cut=%d: synthesized hello", reason, recordSplit, cut)
				}
			}
		}
		w := &helloWriter{}
		ClientHelloDecoder.Writer = w
		records.records = nil
		h.conversation.Data = core.DataFragments{&core.StreamData{RawData: recordWire(22, message), TCPObservation: reason}}
		h.Decode()
		if len(w.messages) != 1 || !strings.Contains(w.messages[0].(*types.TLSClientHello).ReassemblyStatus, reason+"; endpoint delivery unconfirmed") {
			t.Fatalf("missing qualified standalone hello: %v", w.messages)
		}
		if len(records.records) != 1 || records.records[0].TCPObservation != reason {
			t.Fatalf("unqualified TLS records: %v", records.records)
		}
	}
}

func TestTLSStandaloneServerObservation(t *testing.T) {
	h, records := recordTestSetup(t)
	old, count := ServerHelloDecoder.Writer, ServerHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ServerHelloDecoder.Writer, ServerHelloDecoder.NumRecordsWritten = old, count })
	w := &helloWriter{}
	ServerHelloDecoder.Writer = w
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0xc0, 0x2f, 0, 0, 0)
	wire := recordWire(22, append([]byte{2, 0, 0, byte(len(body))}, body...))
	h.conversation.ServerData = core.DataFragments{&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: wire, TCPObservation: "after-fin"}}
	h.Decode()
	if len(w.messages) != 1 || w.messages[0].(*types.TLSServerHello).ReassemblyStatus != "after-fin; endpoint delivery unconfirmed" {
		t.Fatalf("missing qualified standalone server hello: %v", w.messages)
	}
	if len(records.records) != 1 || records.records[0].TCPObservation != "after-fin" {
		t.Fatalf("unqualified server record: %v", records.records)
	}
}

func TestTLSCertificateTransportQualification(t *testing.T) {
	h, _ := recordTestSetup(t)
	der, _ := ownedCertificate(t, false, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	ResetCertificates()
	t.Cleanup(ResetCertificates)
	for _, reason := range []string{"", "after-fin", "after-rst"} {
		h.transportObservation = reason
		h.parseCertificate(der, 0, time.Unix(1, 0).UnixNano(), reassembly.TCPDirServerToClient)
	}
	if certificates.Size() != 3 {
		t.Fatal("qualified certificates merged with confirmed observations")
	}
	seen := make(map[string]bool)
	for _, entry := range certificates.Items {
		seen[entry.TCPObservation] = true
	}
	if !seen[""] || !seen["after-fin"] || !seen["after-rst"] {
		t.Fatalf("certificate qualifications: %v", seen)
	}
}

func TestTLSUpgradeTransportBoundary(t *testing.T) {
	h, _ := recordTestSetup(t)
	old, count := ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten
	t.Cleanup(func() { ClientHelloDecoder.Writer, ClientHelloDecoder.NumRecordsWritten = old, count })
	w := &helloWriter{}
	ClientHelloDecoder.Writer = w
	wire := upgradeHello()
	pre, post := fragment(wire[:20], false, 1), fragment(wire[20:], false, 2)
	post.TCPObservation = "after-rst"
	h.conversation.Data = core.DataFragments{pre, post}
	ObserveUpgrade(h.conversation, "")
	if len(w.messages) != 0 {
		t.Fatal("upgrade observer fabricated a hello across RST")
	}
	post = fragment(wire, false, 3)
	post.TCPObservation = "after-rst"
	h.conversation.Data = core.DataFragments{post}
	ObserveUpgrade(h.conversation, "")
	if len(w.messages) != 1 || !strings.Contains(w.messages[0].(*types.TLSClientHello).ReassemblyStatus, "after-rst") {
		t.Fatalf("upgrade observer lost standalone qualification: %v", w.messages)
	}
}
