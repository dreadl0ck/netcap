package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/encoder"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

type recordTestWriter struct {
	netio.AuditRecordWriter
	records []*types.TLSRecord
}

func (w *recordTestWriter) Write(msg proto.Message) error {
	w.records = append(w.records, proto.Clone(msg).(*types.TLSRecord))
	return nil
}

func recordTestSetup(t *testing.T) (*tlsReader, *recordTestWriter) {
	t.Helper()
	certWriter, recordWriter, count := Decoder.Writer, RecordDecoder.Writer, RecordDecoder.NumRecordsWritten
	t.Cleanup(func() {
		Decoder.Writer, RecordDecoder.Writer, RecordDecoder.NumRecordsWritten = certWriter, recordWriter, count
	})
	w := &recordTestWriter{}
	Decoder.Writer, RecordDecoder.Writer = nil, w
	return &tlsReader{conversation: &core.ConversationInfo{Ident: "test-flow", CommunityID: "community", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 12345, ServerPort: 443}}, w
}

func recordWire(typ byte, body []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

func recordHello(typ byte) []byte {
	body := append([]byte{typ, 0, 0, 38, 3, 3}, make([]byte, 36)...)
	return recordWire(22, body)
}

func TestTLSRecordBoundaries(t *testing.T) {
	h, _ := recordTestSetup(t)
	wire := append(recordHello(2), recordWire(21, []byte{2, 40})...)
	wire = append(wire, recordWire(23, []byte{1, 0, 2, 3})...)
	for split := 0; split <= len(wire); split++ {
		var records []*types.TLSRecord
		f := &tlsRecordFramer{reader: h, dir: reassembly.TCPDirServerToClient, emit: func(r *types.TLSRecord) { records = append(records, r) }}
		f.feed(wire[:split], 123)
		f.feed(wire[split:], 456)
		f.eof()
		if len(records) != 3 {
			t.Fatalf("split %d: %v", split, records)
		}
		for i, r := range records {
			if r.Incomplete || !r.HeaderComplete || r.Status != "complete" || r.Index != uint64(i) || r.RecordVersion != 0x303 || r.SrcIP != "192.0.2.2" || r.DstPort != 12345 || r.CommunityID != "community" {
				t.Fatalf("split %d: %v", split, r)
			}
		}
		if records[0].Offset != 0 || records[1].Offset != uint64(len(recordHello(2))) || records[2].Offset != uint64(len(recordHello(2))+7) {
			t.Fatal("offsets")
		}
		wantTime := int64(123)
		if split == 0 {
			wantTime = 456
		}
		if records[0].Timestamp != wantTime || !records[1].PlaintextAlert || records[1].AlertLevel != 2 || records[1].AlertDescription != 40 || records[2].PlaintextAlert || records[2].AlertState != "" {
			t.Fatalf("timestamp/alert: %v", records)
		}
	}
	var records []*types.TLSRecord
	f := &tlsRecordFramer{reader: h, emit: func(r *types.TLSRecord) { records = append(records, r) }}
	for i := range wire {
		f.feed(wire[i:i+1], int64(i+1))
	}
	f.eof()
	if len(records) != 3 || records[0].Timestamp != 1 || records[1].Timestamp != int64(len(recordHello(2))+1) {
		t.Fatal("bytewise framing")
	}
}

func TestTLSRecordLossEOFAndLimits(t *testing.T) {
	h, _ := recordTestSetup(t)
	for n := 1; n < 9; n++ {
		wire := recordWire(23, []byte{1, 2, 3, 4})
		for _, gap := range []int{0, 10, -1} {
			var records []*types.TLSRecord
			f := &tlsRecordFramer{reader: h, emit: func(r *types.TLSRecord) { records = append(records, r) }}
			f.feed(wire[:n], 1)
			if gap != 0 {
				f.gap(gap, 2)
				f.feed(wire, 3)
			}
			f.eof()
			if len(records) != 1 || !records[0].Incomplete || records[0].Loss != (gap != 0) || records[0].SkippedBytes != int64(gap) || records[0].HeaderComplete != (n >= 5) {
				t.Fatalf("cut=%d gap=%d: %v", n, gap, records)
			}
		}
	}
	for _, wire := range [][]byte{{22, 3, 3, 0xff, 0xff}, {22, 3, 4, 0, 0}, {22, 2, 0, 0, 0}} {
		var records []*types.TLSRecord
		f := &tlsRecordFramer{reader: h, emit: func(r *types.TLSRecord) { records = append(records, r) }}
		f.feed(append(wire, recordHello(2)...), 1)
		if len(records) != 1 || records[0].Status != "invalid_header" || !records[0].Incomplete || len(f.handshake) != 0 {
			t.Fatalf("invalid header: %v", records)
		}
	}
	var records []*types.TLSRecord
	f := &tlsRecordFramer{reader: h, emit: func(r *types.TLSRecord) { records = append(records, r) }}
	f.feed(recordWire(23, make([]byte, maxTLSRecordBody)), 1)
	if len(records) != 1 || records[0].ObservedLength != maxTLSRecordBody || len(f.handshake) != 0 {
		t.Fatal("maximum body framing")
	}
	unknown := recordWire(99, []byte{1, 2})
	f.feed(unknown, 2)
	if len(records) != 2 || records[1].ContentType != 99 || records[1].Status != "unknown_type" {
		t.Fatal("unknown record")
	}
}

func TestTLSRecordEncryptedAlerts(t *testing.T) {
	h, _ := recordTestSetup(t)
	for _, prefix := range [][]byte{nil, append(recordHello(2), recordWire(20, []byte{1})...), append(recordHello(2), recordWire(23, []byte{2, 40})...)} {
		var records []*types.TLSRecord
		f := &tlsRecordFramer{reader: h, emit: func(r *types.TLSRecord) { records = append(records, r) }}
		f.feed(append(prefix, recordWire(21, []byte{2, 40})...), 1)
		r := records[len(records)-1]
		if r.PlaintextAlert || r.AlertLevel != 0 || r.AlertDescription != 0 || r.AlertState != "encrypted_or_unknown" {
			t.Fatalf("invented plaintext alert: %v", r)
		}
	}
	for _, body := range [][]byte{{1}, {3, 40}, {2, 40, 0}} {
		var records []*types.TLSRecord
		f := &tlsRecordFramer{reader: h, emit: func(r *types.TLSRecord) { records = append(records, r) }}
		f.feed(append(recordHello(2), recordWire(21, body)...), 1)
		if records[1].PlaintextAlert || records[1].AlertState != "malformed" {
			t.Fatal("malformed alert")
		}
	}
}

func TestTLSRecordMetadataOnlyDirectionsAndExports(t *testing.T) {
	h, w := recordTestSetup(t)
	client, server := recordHello(1), recordHello(2)
	fragment := func(data []byte, dir reassembly.TCPFlowDirection, ts int64) *core.StreamData {
		return &core.StreamData{RawData: data, Dir: dir, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, ts)}}
	}
	// Per-direction order wins over backwards capture timestamps and merged data.
	h.conversation.ClientData = core.DataFragments{fragment(client[:2], reassembly.TCPDirClientToServer, 200), fragment(client[2:], reassembly.TCPDirClientToServer, 100)}
	h.conversation.ServerData = core.DataFragments{fragment(server, reassembly.TCPDirServerToClient, 300)}
	h.conversation.ServerData = append(h.conversation.ServerData, &core.StreamData{Dir: reassembly.TCPDirServerToClient, SkippedBytes: 10})
	h.conversation.Data = core.DataFragments{fragment([]byte("not stream order"), reassembly.TCPDirClientToServer, 1)}
	h.Decode()
	if len(w.records) != 3 || w.records[0].Timestamp != 200 || w.records[0].SrcPort != 12345 || w.records[1].SrcPort != 443 || w.records[2].Status != "gap" || w.records[2].Index != 1 {
		t.Fatalf("metadata only: %v", w.records)
	}
	encoder.SetConfig(&encoder.Config{MinMax: true})
	for _, r := range w.records {
		wire, err := proto.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		restored := netio.InitRecord(types.Type_NC_TLSRecord)
		if err := proto.Unmarshal(wire, restored); err != nil || !proto.Equal(r, restored) {
			t.Fatalf("roundtrip: %v", err)
		}
		if len(r.CSVHeader()) != len(r.CSVRecord()) || len(r.Encode()) != len(r.CSVHeader()) {
			t.Fatal("export column mismatch")
		}
		ts := r.Time()
		json, err := r.JSON()
		if err != nil || !strings.Contains(json, "test-flow") || r.Time() != ts || strings.Contains(json, "Payload") {
			t.Fatalf("JSON: %s %v", json, err)
		}
		r.Inc()
	}
	if !Decoder.CanDecodeStream(recordWire(21, []byte{2, 40}), nil) {
		t.Fatal("metadata-only detection")
	}
	if !Decoder.CanDecodeStream([]byte{22, 3, 3}, nil) {
		t.Fatal("truncated record header detection")
	}
}

func TestTLSRecordCertificateCoexistence(t *testing.T) {
	h, w := recordTestSetup(t)
	Decoder.Writer = w // Certificates are cached, not sent to this writer during Decode.
	ResetCertificates()
	t.Cleanup(ResetCertificates)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "record-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	length24 := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	cert := append(length24(len(der)+3), length24(len(der))...)
	cert = append(cert, der...)
	handshake := append([]byte{11}, length24(len(cert))...)
	handshake = append(handshake, cert...)
	// A certificate handshake split across records, then across TCP fragments.
	wire := append(recordHello(2), recordWire(22, handshake[:7])...)
	wire = append(wire, recordWire(22, handshake[7:])...)
	for i := range wire {
		h.conversation.ServerData = append(h.conversation.ServerData, &core.StreamData{RawData: wire[i : i+1], Dir: reassembly.TCPDirServerToClient, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}})
	}
	h.Decode()
	if GetCertificateCount() != 1 || len(w.records) != 3 {
		t.Fatalf("certificates=%d records=%d", GetCertificateCount(), len(w.records))
	}
	for _, r := range w.records {
		if r.Incomplete {
			t.Fatal("incomplete certificate record")
		}
	}
	ResetCertificates()
	RecordDecoder.Writer = nil
	h.Decode()
	if GetCertificateCount() != 1 || len(w.records) != 3 {
		t.Fatal("certificate-only decoding")
	}
	// Only certificate extraction is bounded by the handshake limit; metadata continues.
	f := &tlsRecordFramer{reader: h, dir: reassembly.TCPDirServerToClient, emit: func(r *types.TLSRecord) {}}
	f.feed(recordWire(22, append([]byte{11, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0}, 10)...)), 1)
	if !f.certificateLimit || len(f.handshake) != 0 || f.stopped {
		t.Fatal("handshake bound")
	}
}
