package collector

import (
	"os/exec"
	"path/filepath"
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
	}{
		{"ptpv2.pcap", "PTPv2", func() proto.Message { return new(types.PTPv2) }},
		{"iec61850_goose_vlan.pcap", "GOOSE", func() proto.Message { return new(types.GOOSE) }},
		{"iec61850_sv_multi_asdu.pcap", "SampledValues", func() proto.Message { return new(types.SampledValues) }},
		{"ethercat.pcap", "EtherCAT", func() proto.Message { return new(types.EtherCAT) }},
		{"iec104.pcap", "IEC104", func() proto.Message { return new(types.IEC104) }},
		{"iec61850_mms.pcap", "MMS", func() proto.Message { return new(types.MMS) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(strings.TrimSpace(string(root)), "layers/testdata", tc.file)
			count := 0
			for _, workers := range []int{1, 3} {
				out := runVoIP(t, path, tc.name, workers)
				records := bookRecords(t, out, tc.name, tc.new)
				if len(records) == 0 || count != 0 && len(records) != count {
					t.Fatalf("workers=%d records=%d previous=%d", workers, len(records), count)
				}
				count = len(records)
				t.Logf("%d records", count)
			}
		})
	}
}
