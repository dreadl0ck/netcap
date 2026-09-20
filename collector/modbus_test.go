package collector_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/cmd/dump"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func TestModbusSyntheticPCAP(t *testing.T) {
	// Collector and dump use process globals; do not parallelize these cases.
	for _, scenario := range []struct{ missingSYN, payload bool }{{false, true}, {true, true}, {false, false}} {
		missingSYN := scenario.missingSYN
		name := "handshake"
		if missingSYN {
			name = "AllowMissingInit"
		}
		if !scenario.payload {
			name += "_payload_disabled"
		}
		t.Run(name, func(t *testing.T) {
			tcp.ResetStreamFactory()
			t.Cleanup(tcp.ResetStreamFactory)
			dir := t.TempDir()
			pcapPath := filepath.Join(dir, "plant.pcap")
			want := writeModbusHuntPCAP(t, pcapPath, missingSYN)
			if !scenario.payload {
				for i := range want {
					want[i].Payload = nil
				}
			}
			out := filepath.Join(dir, "modbus-hunt")
			// Equivalent to the guide's capture flags, with offline resolvers disabled.
			c := collector.New(collector.Config{
				Workers: 1, PacketBufferSize: 100, SnapLen: defaults.SnapLen,
				ReassembleConnections: true, OutDirPermission: 0o755,
				BaseLayer: utils.GetBaseLayer("ethernet"), DecodeOptions: utils.GetDecodeOptions("default"),
				DecoderConfig: &config.Config{
					Buffer: true, Compression: true, Proto: true, IncludeDecoders: "Modbus",
					Out: out, Source: pcapPath, IncludePayloads: scenario.payload, AddContext: true,
					MemBufferSize: defaults.BufferSize, FlushEvery: defaults.FlushEvery,
					CompressionBlockSize: defaults.CompressionBlockSize, CompressionLevel: defaults.CompressionLevel,
					NumStreamWorkers: 1, StreamBufferSize: 100, Quiet: true,
					NoOptCheck: true, AllowMissingInit: missingSYN,
				},
			})
			if err := c.CollectPcap(pcapPath); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(out, "Modbus.ncap.gz")
			compressed, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(compressed, []byte{0x1f, 0x8b}) {
				t.Fatal("output is not gzip")
			}
			r, err := netio.Open(path, defaults.BufferSize)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			h, err := r.ReadHeader()
			if err != nil {
				t.Fatal(err)
			}
			if h.Type != types.Type_NC_Modbus || h.ContainsPayloads != scenario.payload {
				t.Fatalf("unexpected header: %+v", h)
			}
			var records []types.Modbus
			for {
				var record types.Modbus
				if err := r.Next(&record); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
			checkModbusHuntRecords(t, records, want)
			for _, query := range []struct {
				name, expression string
				indices          []int
			}{
				{"all", "", []int{0, 1, 2, 3, 4, 5, 6}},
				{"writes", `(SrcIP == "192.0.2.20" || DstIP == "192.0.2.20") && UnitID == 1 && FunctionCode in [5, 6, 15, 16, 21, 22, 23]`, []int{0, 1, 2, 3}},
				{"unauthorized", `DstIP == "192.0.2.20" && UnitID == 1 && FunctionCode in [5, 6, 15, 16, 21, 22, 23] && !(SrcIP in ["192.0.2.10", "192.0.2.11"])`, []int{2}},
				{"diagnostics", `FunctionCode in [8, 43]`, []int{5, 6}},
				{"exceptions", `Exception`, []int{3}},
				{"write_ranges", `ParseStatus == "valid" && !Exception && Bank == "holding_registers" && HasAddress && Address == 0 && Quantity == 1 && Values[0] == 1`, []int{0, 1, 2}},
				{"device_id", `ParseStatus == "valid" && MEIType == 14 && ReadDeviceIDCode == 1`, []int{6}},
			} {
				t.Run(query.name, func(t *testing.T) {
					args := []string{"dump", "-read", path, "-json"}
					if query.expression != "" {
						args = append(args, "-filter", query.expression)
					}
					var expected []types.Modbus
					for _, index := range query.indices {
						expected = append(expected, want[index])
					}
					checkModbusHuntRecords(t, runModbusHuntDump(t, args), expected)
				})
			}
			if !missingSYN {
				for _, query := range []struct {
					name, expression string
					indices          []int
				}{
					{"requests", `MessageRole == "request"`, []int{0, 2, 4, 5, 6}},
					{"responses", `MessageRole == "response"`, []int{1, 3}},
					{"matched", `CorrelationStatus == "matched" && ResponseLatency == 1000000`, []int{1, 3}},
					{"write_requests", `MessageRole == "request" && HasAddress && Bank == "holding_registers" && Address + Quantity <= 1`, []int{0, 2, 4}},
				} {
					t.Run(query.name, func(t *testing.T) {
						var expected []types.Modbus
						for _, index := range query.indices {
							expected = append(expected, want[index])
						}
						checkModbusHuntRecords(t, runModbusHuntDump(t, []string{"dump", "-read", path, "-json", "-filter", query.expression}), expected)
					})
				}
			}
		})
	}
}

func writeModbusHuntPCAP(t *testing.T, path string, missingSYN bool) []types.Modbus {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 123456789)
	write := func(src, dst string, segment *layers.TCP, payload []byte) int64 {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
		if err := segment.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, segment, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
		result := stamp.UnixNano()
		stamp = stamp.Add(time.Millisecond)
		return result
	}
	var want []types.Modbus
	for flow, master := range []string{"192.0.2.10", "192.0.2.99"} {
		const plc = "192.0.2.20"
		port := layers.TCPPort(40000 + flow)
		clientSeq, serverSeq := uint32(1001), uint32(2001)
		if !missingSYN {
			write(master, plc, &layers.TCP{SrcPort: port, DstPort: 502, Seq: 1000, SYN: true, Window: 65535}, nil)
			write(plc, master, &layers.TCP{SrcPort: 502, DstPort: port, Seq: 2000, Ack: clientSeq, SYN: true, ACK: true, Window: 65535}, nil)
			write(master, plc, &layers.TCP{SrcPort: port, DstPort: 502, Seq: clientSeq, Ack: serverSeq, ACK: true, Window: 65535}, nil)
		}
		type message struct {
			reply bool
			unit  byte
			pdu   []byte
		}
		messages := []message{
			{false, 1, []byte{6, 0, 0, 0, 1}},
			{true, 1, []byte{6, 0, 0, 0, 1}},
		}
		if flow == 1 {
			messages[1].pdu = []byte{0x86, 2}
			messages = append(messages,
				message{false, 2, []byte{6, 0, 0, 0, 2}},
				message{false, 1, []byte{8, 0, 0, 0x12, 0x34}},
				message{false, 1, []byte{43, 14, 1, 0}},
			)
		}
		for i, message := range messages {
			tid := uint16(flow*10 + i + 1)
			if message.reply {
				tid-- // Replies share the request's transaction number.
			}
			adu := make([]byte, 7+len(message.pdu))
			binary.BigEndian.PutUint16(adu, tid)
			binary.BigEndian.PutUint16(adu[4:], uint16(1+len(message.pdu)))
			adu[6] = message.unit
			copy(adu[7:], message.pdu)
			src, dst, srcPort, dstPort := master, plc, port, layers.TCPPort(502)
			seq, ack := &clientSeq, &serverSeq
			if message.reply {
				src, dst, srcPort, dstPort = plc, master, 502, port
				seq, ack = &serverSeq, &clientSeq
			}
			var timestamp int64
			// Split one ADU across packets to verify first-byte timestamp fidelity.
			parts := [][]byte{adu}
			if flow == 1 && i == 2 {
				parts = [][]byte{adu[:5], adu[5:]}
			}
			for j, part := range parts {
				ts := write(src, dst, &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: *seq, Ack: *ack, ACK: true, PSH: true, Window: 65535}, part)
				if j == 0 {
					timestamp = ts
				}
				*seq += uint32(len(part))
			}
			want = append(want, types.Modbus{Timestamp: timestamp, TransactionID: int32(tid), Length: int32(1 + len(message.pdu)), UnitID: int32(message.unit), Payload: message.pdu, FunctionCode: int32(message.pdu[0] & 0x7f), Exception: message.pdu[0]&0x80 != 0, SrcIP: src, DstIP: dst, SrcPort: int32(srcPort), DstPort: int32(dstPort)})
			m := &want[len(want)-1]
			m.HasMBAP = true
			m.Transport, m.ParseStatus, m.MessageRole, m.CorrelationStatus = "tcp", "valid", "request", "not_applicable"
			if missingSYN {
				m.MessageRole, m.CorrelationStatus = "unknown", "ambiguous"
			}
			if message.reply && (!missingSYN || m.Exception) {
				m.MessageRole, m.CorrelationStatus = "response", "unmatched"
				if !missingSYN {
					m.CorrelationStatus = "matched"
					m.RequestTimestamp = want[len(want)-2].Timestamp
					m.ResponseLatency = timestamp - m.RequestTimestamp
				}
			}
			switch m.FunctionCode {
			case 6:
				m.Bank = "holding_registers"
				if m.Exception {
					m.ExceptionCode = 2
				} else {
					m.HasAddress, m.Quantity, m.Values = true, 1, []uint32{uint32(message.pdu[4])}
				}
			case 8:
				m.HasDiagnostic, m.DiagnosticData = true, []byte{0x12, 0x34}
			case 43:
				m.MEIType, m.ReadDeviceIDCode = 14, 1
				m.MessageRole, m.CorrelationStatus = "request", "not_applicable"
			}
		}
	}
	return want
}

func checkModbusHuntRecords(t *testing.T, got, want []types.Modbus) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(got), len(want), got)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Timestamp < got[j].Timestamp })
	for i := range got {
		if got[i].CommunityID == "" {
			t.Errorf("record %d: missing CommunityID", i)
		}
		got[i].CommunityID = ""
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("record %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func runModbusHuntDump(t *testing.T, args []string) []types.Modbus {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "dump-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdout := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = stdout }()
	command := &cli.Command{Name: "dump", Flags: dump.GetFlags(), Action: dump.RunWithContext}
	if err := command.Run(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var records []types.Modbus
	decoder := json.NewDecoder(f)
	for {
		var record types.Modbus
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("dump JSON: %v", err)
		}
		records = append(records, record)
	}
	return records
}
