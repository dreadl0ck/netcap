package packet

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
)

func TestTCPMPTCP(t *testing.T) {
	previous := conf
	conf = &config.Config{}
	t.Cleanup(func() { conf = previous })
	encoder.SetConfig(&encoder.Config{MinMax: true})
	for _, tt := range []struct {
		name   string
		option []byte
		check  func(*types.TCPMPTCPOption) bool
	}{
		{"capable", []byte{30, 24, 1, 0x81, 1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 0, 10}, func(m *types.TCPMPTCPOption) bool {
			return m.Capable != nil && m.Capable.Version == 1 && m.Capable.Flags == 129 && len(m.Capable.SenderKey) == 8 && len(m.Capable.ReceiverKey) == 8 && m.Capable.DataLength == 9 && m.Capable.Checksum == 10
		}},
		{"join syn", []byte{30, 12, 0x11, 2, 0, 0, 0, 3, 0, 0, 0, 4}, func(m *types.TCPMPTCPOption) bool {
			return m.Join != nil && m.Join.Backup && m.Join.AddressID == 2 && m.Join.ReceiverToken == 3 && m.Join.SenderRandom == 4
		}},
		{"join synack", []byte{30, 16, 0x11, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 9}, func(m *types.TCPMPTCPOption) bool {
			return m.Join != nil && len(m.Join.SenderHMAC) == 8 && m.Join.SenderRandom == 9
		}},
		{"join ack", append([]byte{30, 24, 0x10, 0}, make([]byte, 20)...), func(m *types.TCPMPTCPOption) bool { return m.Join != nil && len(m.Join.SenderHMAC) == 20 }},
		{"dss64", append([]byte{30, 28, 0x20, 0x1f}, make([]byte, 24)...), func(m *types.TCPMPTCPOption) bool {
			return m.DSS != nil && m.DSS.ACK64 && m.DSS.DSN64 && m.DSS.DataFIN && m.DSS.MappingPresent && m.DSS.ACKPresent && m.DSS.ChecksumPresent && len(m.DSS.DSN) == 8 && len(m.DSS.DataACK) == 8
		}},
		{"dss32", []byte{30, 18, 0x20, 5, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 4}, func(m *types.TCPMPTCPOption) bool {
			return m.DSS != nil && !m.DSS.ACK64 && !m.DSS.DSN64 && !m.DSS.ChecksumPresent && m.DSS.SubflowSequence == 3 && m.DSS.DataLength == 4
		}},
		{"add v0", []byte{30, 10, 0x34, 7, 192, 0, 2, 1, 1, 187}, func(m *types.TCPMPTCPOption) bool {
			return m.AddAddr != nil && m.AddAddr.IPVersion == 4 && m.AddAddr.AddressID == 7 && m.AddAddr.Address == "192.0.2.1" && m.AddAddr.Port == 443
		}},
		{"add v1", []byte{30, 16, 0x30, 7, 192, 0, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8}, func(m *types.TCPMPTCPOption) bool {
			return m.AddAddr != nil && !m.AddAddr.Echo && bytes.Equal(m.AddAddr.SenderHMAC, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		}},
		{"add v6 echo", append([]byte{30, 20, 0x31, 7}, make([]byte, 16)...), func(m *types.TCPMPTCPOption) bool {
			return m.AddAddr != nil && m.AddAddr.Echo && m.AddAddr.Address == "::"
		}},
		{"remove", []byte{30, 5, 0x40, 1, 2}, func(m *types.TCPMPTCPOption) bool {
			return m.RemoveAddr != nil && len(m.RemoveAddr.AddressIDs) == 2 && m.RemoveAddr.AddressIDs[1] == 2
		}},
		{"priority", []byte{30, 4, 0x51, 7}, func(m *types.TCPMPTCPOption) bool {
			return m.Priority != nil && m.Priority.Backup && m.Priority.AddressID == 7 && m.Priority.AddressIDPresent
		}},
		{"priority no id", []byte{30, 3, 0x50}, func(m *types.TCPMPTCPOption) bool { return m.Priority != nil && !m.Priority.AddressIDPresent }},
		{"fail", []byte{30, 12, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 7}, func(m *types.TCPMPTCPOption) bool { return m.Fail != nil && m.Fail.DSN == 7 }},
		{"close", []byte{30, 12, 0x70, 0, 1, 2, 3, 4, 5, 6, 7, 8}, func(m *types.TCPMPTCPOption) bool { return m.FastClose != nil && len(m.FastClose.ReceiverKey) == 8 }},
		{"reset", []byte{30, 4, 0x8f, 3}, func(m *types.TCPMPTCPOption) bool {
			return m.TCPReset != nil && m.TCPReset.U && m.TCPReset.V && m.TCPReset.W && m.TCPReset.Transient && m.TCPReset.Reason == 3
		}},
		{"unknown", []byte{30, 5, 0xf7, 0xaa, 0xff}, func(m *types.TCPMPTCPOption) bool { return m.Subtype == 15 && m.Capable == nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := append(make([]byte, 20), 1) // NOP before MPTCP exercises option indexing.
			data = append(data, tt.option...)
			data = append(data, 0)
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
			data[12] = byte(len(data)/4) << 4
			data = append(data, 30, 4, 0x80, 1) // Payload must not enter the option walk.
			var tcp layers.TCP
			if err := tcp.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				t.Fatal(err)
			}
			if len(tcp.Options[1].OptionData) != 0 {
				t.Fatal("upstream raw-data assumption changed")
			}
			record := tcpDecoder.Handler(&tcp, 123).(*types.TCP)
			o := record.Options[1]
			if !record.Multipath || !bytes.Equal(o.Raw, tt.option) || !bytes.Equal(o.OptionData, tt.option[2:]) || !tt.check(o.MPTCP) {
				t.Fatalf("bad option: %v", o)
			}
			wire, err := proto.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip types.TCP
			if err = proto.Unmarshal(wire, &roundtrip); err != nil || !proto.Equal(record, &roundtrip) {
				t.Fatalf("roundtrip: %v", err)
			}
			record.SrcIP, record.DstIP = "192.0.2.1", "192.0.2.2"
			if len(record.CSVRecord()) != len(record.CSVHeader()) || len(record.Encode()) != len(record.CSVHeader()) {
				t.Fatal("export column mismatch")
			}
			json, err := record.JSON()
			if err != nil || !strings.Contains(json, "MPTCP") {
				t.Fatalf("JSON export: %s %v", json, err)
			}
			data[23] ^= 0xff
			if !bytes.Equal(o.Raw, tt.option) {
				t.Fatal("raw option aliases packet")
			}
		})
	}
}

func TestTCPRawOptionsBounds(t *testing.T) {
	for _, data := range [][]byte{nil, make([]byte, 19), append(make([]byte, 20), 30), append(make([]byte, 20), 30, 0, 0, 0), append(make([]byte, 20), 30, 255, 0, 0)} {
		tcp := &layers.TCP{BaseLayer: layers.BaseLayer{Contents: data}, DataOffset: 15, Multipath: true}
		if got := tcpRawOptions(tcp); len(got) != 0 {
			t.Fatalf("unbounded options: %x", got)
		}
	}
}
