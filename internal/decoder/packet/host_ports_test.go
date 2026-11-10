package packet

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestHostPortIndexPreservesOrderCountersAndProtocol(t *testing.T) {
	p := &hostEntry{Host: &types.Host{}}
	for _, update := range []func(*hostEntry, int32, string, uint64){doSrcPortUpdate, doDstPortUpdate, doContactedPortUpdate} {
		for n := int32(0); n < 65536; n++ {
			update(p, n, "TCP", 64)
			update(p, n, "UDP", 32)
		}
		update(p, 0, "TCP", 16)
		update(p, 65535, "UDP", 8)
	}
	for _, ports := range [][]*types.Port{p.SrcPorts, p.DstPorts, p.ContactedPorts} {
		if len(ports) != 2*65536 {
			t.Fatal("ports merged or lost", len(ports))
		}
		for i, port := range ports {
			protocol, bytes, packets := "TCP", uint64(64), uint64(1)
			if i%2 != 0 {
				protocol, bytes = "UDP", 32
			}
			if i == 0 {
				bytes, packets = 80, 2
			}
			if i == len(ports)-1 {
				bytes, packets = 40, 2
			}
			if port.PortNumber != int32(i/2) || port.Protocol != protocol || port.Stats.Bytes != bytes || port.Stats.Packets != packets {
				t.Fatalf("port %d: %v", i, port)
			}
		}
	}
}

func BenchmarkHostScanPortUpdate(b *testing.B) {
	p := &hostEntry{Host: &types.Host{}}
	for n := int32(0); n < 65536; n++ {
		doSrcPortUpdate(p, n, "TCP", 64)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doSrcPortUpdate(p, int32(i%65536), "TCP", 64)
	}
}
