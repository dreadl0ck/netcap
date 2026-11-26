package collector

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// Use captures from the checksum-pinned dependency rather than copying its corpus.
func TestIndustrialReplay(t *testing.T) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/gopacket/gopacket").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file, name string
		new        func() proto.Message
		want       int
		match      func(proto.Message) bool
	}{
		{"ptpv2.pcap", "PTPv2", func() proto.Message { return new(types.PTPv2) }, 39, func(m proto.Message) bool { return m.(*types.PTPv2).SequenceID == 1118 }},
		{"iec61850_goose_vlan.pcap", "GOOSE", func() proto.Message { return new(types.GOOSE) }, 1, func(m proto.Message) bool {
			r := m.(*types.GOOSE)
			return r.State == 1 && r.ControlBlock != "" && r.Src() != "" && r.Dst() != "" && strings.Contains(r.Context.GetNetworkScope(), "vlan:")
		}},
		{"iec61850_sv_multi_asdu.pcap", "SampledValues", func() proto.Message { return new(types.SampledValues) }, 20, func(m proto.Message) bool {
			return slices.Equal(m.(*types.SampledValues).SampleCounter, []uint32{27220, 27221, 27222, 27223, 27224})
		}},
		{"ethercat.pcap", "EtherCAT", func() proto.Message { return new(types.EtherCAT) }, 437, func(m proto.Message) bool {
			r := m.(*types.EtherCAT)
			return len(r.Commands) == 7 && len(r.WorkingCounters) == 7
		}},
		{"iec104.pcap", "IEC104", func() proto.Message { return new(types.IEC104) }, 115, func(m proto.Message) bool {
			r := m.(*types.IEC104)
			return r.UFunction != "" && r.Assembly.GetStatus() == "complete"
		}},
		{"iec61850_mms.pcap", "MMS", func() proto.Message { return new(types.MMS) }, 163, func(m proto.Message) bool { r := m.(*types.MMS); return r.InvokeID == 4431 && r.Service != "" }},
		{"s7commplus-1200-upload.pcap", "S7Comm", func() proto.Message { return new(types.S7Comm) }, 90, func(m proto.Message) bool {
			r := m.(*types.S7Comm)
			return r.Assembly.GetStatus() == "complete" && r.Assembly.Pieces == 3 && r.Timestamp == 1387554088163307000 && r.S7PlusFunction == 0x04ca && r.DataLength == 2219
		}},
		{"opcua-read.pcap", "OPCUA", func() proto.Message { return new(types.OPCUA) }, 18, func(m proto.Message) bool {
			r := m.(*types.OPCUA)
			return r.ServiceName == "ReadRequest" && r.IsRequest && r.Assembly.GetStatus() == "complete"
		}},
		{"opcua-encrypted.pcap", "OPCUA", func() proto.Message { return new(types.OPCUA) }, 14, func(m proto.Message) bool {
			r := m.(*types.OPCUA)
			return r.MessageType == "MSG" && r.Assembly.GetStatus() == "opaque" && r.ServiceName == "" && r.RequestId == 0 && len(r.Payload) == 0
		}},
		{"opcua-signed.pcap", "OPCUA", func() proto.Message { return new(types.OPCUA) }, 10, func(m proto.Message) bool {
			r := m.(*types.OPCUA)
			return r.Assembly.GetStatus() == "complete" && r.IsRequest && r.ServiceName == "BrowseRequest"
		}},
		{"profinet-extra.pcap", "PROFINET", func() proto.Message { return new(types.PROFINET) }, 64, func(m proto.Message) bool {
			r := m.(*types.PROFINET)
			return r.Assembly.GetStatus() == "complete" && r.Assembly.Pieces == 3 && r.Timestamp == 1795085931000024000 && r.IsRequest && r.SequenceNumber == 0x1234 && r.ServiceID == 5
		}},
		{"profinet-dcp.pcap", "PROFINET", func() proto.Message { return new(types.PROFINET) }, 24, func(m proto.Message) bool {
			r := m.(*types.PROFINET)
			return r.StationName == "X208-BORD" && r.VendorID == "0x002a" && r.DeviceID == "0x0a01" && r.Src() != ""
		}},
		{"bacnet-vectors-ipv6.pcap", "BACnetIP", func() proto.Message { return new(types.BACnetIP) }, 6, func(m proto.Message) bool {
			r := m.(*types.BACnetIP)
			return r.Carrier == "BACnet/IPv6" && strings.Contains(r.SrcIP, ":") && r.BVLCType == 0x82
		}},
		{"bacnet-segmented.pcap", "BACnetIP", func() proto.Message { return new(types.BACnetIP) }, 5, func(m proto.Message) bool {
			r := m.(*types.BACnetIP)
			return r.SegmentedMessage == 1 && r.InvokeID == 1 && r.Assembly.GetStatus() == "complete" && r.Assembly.Pieces > 1 && r.ServiceName == "ReadRange"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(strings.TrimSpace(string(root)), "layers/testdata", tc.file)
			if tc.file == "opcua-signed.pcap" {
				// Loopback capture begins at HEL, after the TCP handshake.
				t.Setenv("NETCAP_TEST_MIDSTREAM", "1")
			}
			var baseline [][]byte
			workerCounts := []int{1, 3}
			switch tc.name {
			case "PTPv2", "GOOSE", "SampledValues", "EtherCAT", "PROFINET", "BACnetIP":
				workerCounts = append(workerCounts, 3)
			}
			for i, workers := range workerCounts {
				if i == 2 {
					t.Setenv("W76_PACKET_ONLY", "1")
				}
				out := runVoIP(t, path, tc.name, workers)
				records := bookRecords(t, out, tc.name, tc.new)
				if len(records) != tc.want || !slices.ContainsFunc(records, tc.match) {
					t.Fatalf("%s: workers=%d, got %d records (want %d) or expected field missing", tc.file, workers, len(records), tc.want)
				}
				if tc.name == "S7Comm" {
					joined, confirmed := 0, 0
					for _, row := range records {
						r := row.(*types.S7Comm)
						if tc.match(row) {
							joined++
						}
						if r.COTPPDUType == 0xd0 && r.COTPSrcRef == 7 && r.COTPDestRef == 0x11 {
							confirmed++
						}
					}
					if joined != 1 || confirmed != 1 {
						t.Fatalf("joined CreateObject=%d, matching COTP CC=%d", joined, confirmed)
					}
				}
				var rows [][]byte
				for _, r := range records {
					wire, err := proto.Marshal(r)
					if err != nil {
						t.Fatal(err)
					}
					rows = append(rows, wire)
				}
				slices.SortFunc(rows, bytes.Compare)
				if baseline != nil && !slices.EqualFunc(rows, baseline, bytes.Equal) {
					t.Fatalf("workers=%d changed the decoded records", workers)
				}
				baseline = rows
			}
		})
	}
}
