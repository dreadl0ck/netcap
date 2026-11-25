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
			return r.State == 1 && r.ControlBlock != "" && strings.Contains(r.Context.GetNetworkScope(), "vlan:")
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(strings.TrimSpace(string(root)), "layers/testdata", tc.file)
			var baseline [][]byte
			for _, workers := range []int{1, 3} {
				out := runVoIP(t, path, tc.name, workers)
				records := bookRecords(t, out, tc.name, tc.new)
				if len(records) != tc.want || !slices.ContainsFunc(records, tc.match) {
					t.Fatalf("%s: workers=%d, got %d records (want %d) or expected field missing", tc.file, workers, len(records), tc.want)
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
