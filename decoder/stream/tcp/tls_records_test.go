package tcp

import (
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

type tlsCaptureWriter struct {
	netio.AuditRecordWriter
	records []*types.TLSRecord
}

func (w *tlsCaptureWriter) Write(msg proto.Message) error {
	w.records = append(w.records, proto.Clone(msg).(*types.TLSRecord))
	return nil
}

type tlsGapSG struct {
	reassembly.ScatterGather
	dir  reassembly.TCPFlowDirection
	skip int
}

func (s tlsGapSG) Lengths() (int, int) { return 3, 0 }
func (s tlsGapSG) Info() (reassembly.TCPFlowDirection, bool, bool, int) {
	return s.dir, false, false, s.skip
}
func (s tlsGapSG) Stats() reassembly.TCPAssemblyStats { return reassembly.TCPAssemblyStats{} }
func (s tlsGapSG) Fetch(n int) []byte                 { return []byte{1, 2, 3}[:n] }

func TestTLSRecordTCPSelectionAndGap(t *testing.T) {
	previous := config.Instance
	certWriter, recordWriter, count := tls.Decoder.Writer, tls.RecordDecoder.Writer, tls.RecordDecoder.NumRecordsWritten
	t.Cleanup(func() {
		config.Instance = previous
		tls.Decoder.Writer, tls.RecordDecoder.Writer, tls.RecordDecoder.NumRecordsWritten = certWriter, recordWriter, count
	})
	c := *config.DefaultConfig
	config.Instance = &c
	tls.Decoder.Writer = nil
	for _, skip := range []int{0, 5, -1} {
		w := &tlsCaptureWriter{}
		tls.RecordDecoder.Writer = w
		// Split inside the record header. The second fragment has an older timestamp.
		conn := newMergeTestConn([]string{string([]byte{23, 3}), string([]byte{3, 0, 2, 1, 2})}, nil, time.Unix(1, 0))
		conn.net = gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
		conn.transport = gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{1, 187})
		client := conn.client.(*tcpStreamReader)
		client.data[1].(*core.StreamData).AssemblerContext = &mergeTestContext{ts: time.Unix(0, 0)}
		if skip != 0 {
			second := client.data[1]
			client.data = client.data[:1]
			conn.ReassembledSG(tlsGapSG{dir: reassembly.TCPDirClientToServer, skip: skip}, &mergeTestContext{ts: time.Unix(2, 0)})
			client.data = append(client.data, second)
		}
		conn.sortAndMergeFragments()
		conn.decode()
		if len(w.records) != 1 || w.records[0].ContentType != 23 || w.records[0].SrcPort != 40000 || w.records[0].DstPort != 443 {
			t.Fatalf("selection: %v", w.records)
		}
		r := w.records[0]
		if skip == 0 {
			if r.Incomplete || r.Length != 2 || r.Timestamp != time.Unix(1, 0).Add(time.Millisecond).UnixNano() {
				t.Fatalf("order/timestamp: %v", r)
			}
		} else {
			wantSkip := int64(skip)
			if skip > 0 {
				wantSkip += 3
			}
			if !r.Loss || !r.Incomplete || r.SkippedBytes != wantSkip {
				t.Fatalf("gap: %v", r)
			}
		}
	}
}
