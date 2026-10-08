package packet

import "testing"

func TestLegacyNetflowTemplateExporterScope(t *testing.T) {
	netflowTemplates.Clear()
	t.Cleanup(netflowTemplates.Clear)
	a := netflowScope{sourceID: 7, srcIP: "192.0.2.1", dstIP: "192.0.2.254", srcPort: 50000, dstPort: 2055}
	b := a
	b.srcIP = "192.0.2.2"
	parseNetflowTemplateFlowSet([]byte{1, 0, 0, 1, 0, 8, 0, 4}, a)
	parseNetflowTemplateFlowSet([]byte{1, 0, 0, 1, 0, 12, 0, 4}, b)
	for _, tc := range []struct {
		scope netflowScope
		want  int32
	}{{a, 8}, {b, 12}} {
		fields := parseNetflowDataFlowSet([]byte{192, 0, 2, 3}, 256, tc.scope)
		if len(fields) != 1 || fields[0].Type != tc.want {
			t.Fatalf("template crossed exporter scope: %+v", fields)
		}
	}
	parseNetflowTemplateFlowSet([]byte{1, 0, 0, 2, 0, 12, 0, 4}, a)
	if fields := parseNetflowDataFlowSet([]byte{192, 0, 2, 3}, 256, a); len(fields) != 1 || fields[0].Type != 8 {
		t.Fatal("truncated template poisoned legacy cache")
	}
}
