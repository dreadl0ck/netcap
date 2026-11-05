package packet

import (
	"fmt"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket/layers"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestConnectionIgnoresAsymmetricMACsButKeepsCaptureScope(t *testing.T) {
	connectionConcurrencySetup(t)
	p := connectionBenchmarkPackets(t, 4)
	p[0].Layer(layers.LayerTypeTCP).(*layers.TCP).SYN = true
	p[0].Layer(layers.LayerTypeTCP).(*layers.TCP).ACK = false
	for i := 1; i < len(p); i++ {
		ip := p[i].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ip.SrcIP = net.IPv4(10, 0, 0, 1)
		tcp := p[i].Layer(layers.LayerTypeTCP).(*layers.TCP)
		tcp.SrcPort = 32768
	}
	replyIP := p[1].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	replyIP.SrcIP, replyIP.DstIP = replyIP.DstIP, replyIP.SrcIP
	replyTCP := p[1].Layer(layers.LayerTypeTCP).(*layers.TCP)
	replyTCP.SrcPort, replyTCP.DstPort = replyTCP.DstPort, replyTCP.SrcPort
	replyTCP.SYN = true
	eth := p[1].Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	eth.SrcMAC = net.HardwareAddr{0, 0, 12, 159, 240, 1}
	eth.DstMAC = net.HardwareAddr{0, 1, 2, 3, 4, 5}
	p[1].Metadata().Timestamp = time.Unix(1700000001, 0)
	p[0] = serializedEvidencePacket(t, p[0], p[0].Metadata().Timestamp)
	p[1] = serializedEvidencePacket(t, p[1], p[1].Metadata().Timestamp)
	handlePacket(p[0])
	handlePacket(p[1])
	if len(conns.Items) != 1 {
		t.Fatal("one TCP connection split by MACs", len(conns.Items))
	}
	for _, c := range conns.Items {
		if c.NumPackets64 != 2 || c.SrcIP != "10.0.0.1" {
			t.Fatal(c.Connection)
		}
	}
	p[2] = serializedEvidencePacket(t, p[2], p[2].Metadata().Timestamp)
	p[2].Metadata().InterfaceIndex = 2
	handlePacket(p[2])
	if len(conns.Items) != 2 {
		t.Fatal("capture interfaces merged")
	}
	tcp := p[3].Layer(layers.LayerTypeTCP).(*layers.TCP)
	tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	p[3] = serializedEvidencePacket(t, p[3], p[3].Metadata().Timestamp)
	handlePacket(p[3])
	if len(conns.Items) != 3 {
		t.Fatal("different endpoint-to-port associations merged")
	}
}

func TestContactsBoundedAndDeduplicated(t *testing.T) {
	p := &deviceProfile{DeviceProfile: &types.DeviceProfile{}}
	for i := 0; i < 70835; i++ {
		observeContact(p, net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String())
	}
	if len(p.contactSet) != maxContactKeys || len(p.Contacts) != maxReportedContacts || !p.ContactsTruncated || p.ContactCountLowerBound != maxContactKeys+1 {
		t.Fatal(len(p.contactSet), len(p.Contacts), p.ContactCountLowerBound)
	}
	before := p.ContactCountLowerBound
	observeContact(p, "10.0.0.1")
	if p.ContactCountLowerBound != before || p.ContactObservations != 70836 {
		t.Fatal("contact counters not qualified", p.DeviceProfile)
	}
}

func BenchmarkContactCardinality(b *testing.B) {
	for _, n := range []int{1000, 10000, 70835} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ips := make([]string, n)
			for i := range ips {
				ips[i] = net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				p := &deviceProfile{DeviceProfile: &types.DeviceProfile{}}
				for _, ip := range ips {
					observeContact(p, ip)
				}
			}
		})
	}
}

func TestContactSampleIndependentOfArrivalOrder(t *testing.T) {
	a := &deviceProfile{DeviceProfile: &types.DeviceProfile{}}
	b := &deviceProfile{DeviceProfile: &types.DeviceProfile{}}
	for i := 0; i < 10000; i++ {
		observeContact(a, fmt.Sprintf("203.0.%d.%d", i>>8, i&255))
		j := 9999 - i
		observeContact(b, fmt.Sprintf("203.0.%d.%d", j>>8, j&255))
	}
	x, y := append([]string(nil), a.contactHeap...), append([]string(nil), b.contactHeap...)
	sort.Strings(x)
	sort.Strings(y)
	if !reflect.DeepEqual(x, y) || a.ContactCountLowerBound != b.ContactCountLowerBound {
		t.Fatal("bounded contact sample depends on worker arrival order")
	}
}
