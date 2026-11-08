package ipp

import (
	"fmt"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

type ippWriter struct {
	netio.AuditRecordWriter
	records []*types.IPP
}

func (w *ippWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.IPP))
	return nil
}

func ippHTTP(server, chunked bool, id byte) []byte {
	body := string([]byte{2, 0, 0, 2, 0, 0, 0, id, 3})
	line := "POST /ipp/print HTTP/1.1\r\n"
	if server {
		line = "HTTP/1.1 200 OK\r\n"
	}
	if chunked {
		return []byte(line + "Content-Type: application/ipp\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n" + body[:4] + "\r\n5\r\n" + body[4:] + "\r\n0\r\n\r\n")
	}
	return []byte(line + "Content-Type: application/ipp\r\nContent-Length: 9\r\n\r\n" + body)
}

func TestIPPHTTPFraming(t *testing.T) {
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	for _, server := range []bool{false, true} {
		for _, chunked := range []bool{false, true} {
			wire := ippHTTP(server, chunked, 7)
			if server {
				wire = append([]byte("HTTP/1.1 100 Continue\r\n\r\n"), wire...)
			}
			firstLen := len(wire)
			wire = append(wire, ippHTTP(server, false, 8)...)
			for split := 1; split < len(wire); split++ {
				t.Run(fmt.Sprintf("server=%t/chunked=%t/split=%d", server, chunked, split), func(t *testing.T) {
					w := &ippWriter{}
					Decoder.Writer = w
					dir := reassembly.TCPDirClientToServer
					if server {
						dir = reassembly.TCPDirServerToClient
					}
					c := &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 12345, ServerPort: 631, Ident: "flow", CommunityID: "1:test",
						Data: core.DataFragments{
							&core.StreamData{RawData: wire[:split], Dir: dir, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(10, 0)}},
							&core.StreamData{RawData: wire[split:], Dir: dir, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(11, 0)}},
						}}
					(&ippReader{conversation: c}).Decode()
					if len(w.records) != 2 {
						t.Fatalf("got %v", w.records)
					}
					for i, rec := range w.records {
						wantName, wantSrc := "Print-Job", c.ClientIP
						if server {
							wantName, wantSrc = "successful-ok-conflicting-attributes", c.ServerIP
						}
						wantTime := time.Unix(10, 0).UnixNano()
						if i == 1 && split <= firstLen || i == 0 && server && split <= len("HTTP/1.1 100 Continue\r\n\r\n") {
							wantTime = time.Unix(11, 0).UnixNano()
						}
						if rec.RequestID != int32(7+i) || rec.OperationName != wantName || rec.SrcIP != wantSrc || rec.Timestamp != wantTime || rec.Flow != c.Ident || rec.CommunityID != c.CommunityID {
							t.Fatalf("bad attribution/message: %v", rec)
						}
					}
				})
			}
		}
	}
}

func TestIPPDoesNotParseUnframedBodies(t *testing.T) {
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	good := ippHTTP(false, false, 7)
	for _, wire := range [][]byte{
		good[:len(good)-1],
		[]byte("POST / HTTP/1.1\r\nContent-Type: application/ipp\r\nTransfer-Encoding: chunked\r\n\r\ninvalid\r\n" + string(good)),
		[]byte("POST / HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: " + fmt.Sprint(len(good)) + "\r\n\r\n" + string(good)),
	} {
		w := &ippWriter{}
		Decoder.Writer = w
		(&ippReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: wire}}}}).Decode()
		if len(w.records) != 0 {
			t.Fatalf("parsed incomplete/non-IPP body: %v", w.records)
		}
	}
	for _, boundary := range []*core.StreamData{{SkippedBytes: 5}, {SkippedBytes: -1}, {DiscardedBytes: 5}, {TCPObservation: "after-fin"}, {TCPObservation: "after-rst"}} {
		w := &ippWriter{}
		Decoder.Writer = w
		boundary.RawData = good[len(good)-4:]
		(&ippReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: good[:len(good)-4]}, boundary}}}).Decode()
		if len(w.records) != 0 {
			t.Fatalf("joined across boundary: %v", w.records)
		}
	}
}

func TestIPPExpectContinueInterleavesDirections(t *testing.T) {
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	w := &ippWriter{}
	Decoder.Writer = w
	request, response := ippHTTP(false, false, 7), ippHTTP(true, false, 7)
	headerLen := len(request) - 9
	(&ippReader{conversation: &core.ConversationInfo{Data: core.DataFragments{
		&core.StreamData{RawData: request[:headerLen]},
		&core.StreamData{RawData: []byte("HTTP/1.1 100 Continue\r\n\r\n"), Dir: reassembly.TCPDirServerToClient},
		&core.StreamData{RawData: request[headerLen:]},
		&core.StreamData{RawData: response, Dir: reassembly.TCPDirServerToClient},
	}}}).Decode()
	if len(w.records) != 2 || w.records[0].RequestID != 7 || w.records[0].OperationName != "Print-Job" || w.records[1].RequestID != 7 || w.records[1].OperationName != "successful-ok-conflicting-attributes" {
		t.Fatalf("lost interleaved transaction: %v", w.records)
	}
}
