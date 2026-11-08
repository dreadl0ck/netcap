package cip

import (
	"bytes"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

type evidenceWriter struct {
	netio.AuditRecordWriter
	records []*types.CIP
}

func TestCIPDirectionalGapAndDatagramBoundaries(t *testing.T) {
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	fragment := func(data []byte, server bool, gap int) *core.StreamData {
		d := &core.StreamData{RawData: data, SkippedBytes: gap, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, 123)}}
		if server {
			d.Dir = reassembly.TCPDirServerToClient
		}
		return d
	}
	for _, tc := range []struct {
		name      string
		transport core.TransportProtocol
		data      core.DataFragments
		count     int
	}{
		{"interleaved", core.TCP, core.DataFragments{fragment(sampleENIPCIPRequest[:30], false, 0), fragment(sampleENIPCIPResponse, true, 0), fragment(sampleENIPCIPRequest[30:], false, 0)}, 2},
		{"gap", core.TCP, core.DataFragments{fragment(sampleENIPCIPRequest[:30], false, 0), fragment(sampleENIPCIPRequest[30:], false, 1)}, 0},
		{"udp", core.UDP, core.DataFragments{fragment(sampleENIPCIPRequest, false, 0), fragment(sampleENIPCIPResponse, true, 0)}, 2},
		{"udp-no-join", core.UDP, core.DataFragments{fragment(sampleENIPCIPRequest[:30], false, 0), fragment(sampleENIPCIPRequest[30:], false, 0)}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &evidenceWriter{}
			Decoder.Writer = w
			(&cipReader{conversation: &core.ConversationInfo{Transport: tc.transport, Data: tc.data, ClientIP: "192.0.2.1", ServerIP: "192.0.2.2"}}).Decode()
			if len(w.records) != tc.count {
				t.Fatalf("got %d want %d", len(w.records), tc.count)
			}
		})
	}
	if Decoder.Typ != core.All {
		t.Fatal("UDP CIP unreachable")
	}
}

func (w *evidenceWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.CIP))
	return nil
}

// The historical packet-layer investigation accepted any one nonzero field.
// Assert the emitted protocol fields and context together after stream framing.
func TestCIPEmittedEvidenceAcrossFragmentBoundaries(t *testing.T) {
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	response := bytes.Clone(sampleENIPCIPResponse)
	response[42], response[43] = 1, 1 // failure plus one additional-status word
	response[44], response[45] = 0x34, 0x12
	fragment := func(data []byte, stamp int64, server bool) *core.StreamData {
		d := &core.StreamData{RawData: data, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, stamp)}}
		if server {
			d.Dir = reassembly.TCPDirServerToClient
		}
		return d
	}
	for split := 1; split < len(sampleENIPCIPRequest); split++ {
		w := &evidenceWriter{}
		Decoder.Writer = w
		conversation := &core.ConversationInfo{
			ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 2430, ServerPort: 44818, CommunityID: "1:cip-evidence",
			ClientData: core.DataFragments{fragment(sampleENIPCIPRequest[:split], 100, false), fragment(sampleENIPCIPRequest[split:], 200, false)},
			ServerData: core.DataFragments{fragment(response[:split], 300, true), fragment(response[split:], 400, true)},
		}
		(&cipReader{conversation: conversation}).Decode()
		if len(w.records) != 2 {
			t.Fatalf("split=%d: got %d records", split, len(w.records))
		}
		request, reply := w.records[0], w.records[1]
		if request.Response || request.ServiceID != 0x4b || request.ClassID != 0x67 || request.InstanceID != 1 || !bytes.Equal(request.Data, sampleENIPCIPRequest[46:]) {
			t.Fatalf("split=%d request=%+v", split, request)
		}
		if !reply.Response || reply.ServiceID != 0x4b || reply.Status != 1 || len(reply.AdditionalStatus) != 1 || reply.AdditionalStatus[0] != 0x1234 || !bytes.Equal(reply.Data, response[46:]) {
			t.Fatalf("split=%d response=%+v", split, reply)
		}
		if request.Timestamp != 100 || reply.Timestamp != 300 || request.SrcIP != conversation.ClientIP || request.DstIP != conversation.ServerIP || request.SrcPort != 2430 || request.DstPort != 44818 || reply.SrcIP != conversation.ServerIP || reply.DstIP != conversation.ClientIP || reply.SrcPort != 44818 || reply.DstPort != 2430 || request.CommunityID != conversation.CommunityID || reply.CommunityID != conversation.CommunityID {
			t.Fatalf("split=%d context lost: request=%+v response=%+v", split, request, reply)
		}
	}
}
