package webui

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func TestConnectionPacketSelectionPairsEndpointsAndTransport(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		a, b := "192.0.2.1", "192.0.2.2"
		if ipv6 {
			a, b = "2001:db8::1", "2001:db8::2"
		}
		selection, err := parseConnectionPacketSelection(url.Values{"srcIP": {a}, "dstIP": {b}, "srcPort": {"12345"}, "dstPort": {"443"}, "protocol": {"TCP"}})
		if err != nil {
			t.Fatal(err)
		}
		bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, selection.bpf)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			src, dst  string
			sp, dp    uint16
			udp, want bool
		}{
			{a, b, 12345, 443, false, true}, {b, a, 443, 12345, false, true},
			{a, b, 443, 12345, false, false}, {b, a, 12345, 443, false, false},
			{a, b, 12345, 443, true, false},
		} {
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
			var network gopacket.SerializableLayer
			if ipv6 {
				eth.EthernetType = layers.EthernetTypeIPv6
				ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst), NextHeader: layers.IPProtocolTCP}
				if tc.udp {
					ip.NextHeader = layers.IPProtocolUDP
				}
				network = ip
			} else {
				ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst), Protocol: layers.IPProtocolTCP}
				if tc.udp {
					ip.Protocol = layers.IPProtocolUDP
				}
				network = ip
			}
			var transport gopacket.SerializableLayer
			if tc.udp {
				udp := &layers.UDP{SrcPort: layers.UDPPort(tc.sp), DstPort: layers.UDPPort(tc.dp)}
				if err := udp.SetNetworkLayerForChecksum(network.(gopacket.NetworkLayer)); err != nil {
					t.Fatal(err)
				}
				transport = udp
			} else {
				tcp := &layers.TCP{SrcPort: layers.TCPPort(tc.sp), DstPort: layers.TCPPort(tc.dp), SYN: true}
				if err := tcp.SetNetworkLayerForChecksum(network.(gopacket.NetworkLayer)); err != nil {
					t.Fatal(err)
				}
				transport = tcp
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, network, transport); err != nil {
				t.Fatal(err)
			}
			data := buf.Bytes()
			if got := bpf.Matches(gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, data); got != tc.want {
				t.Fatalf("IPv6=%v %s:%d -> %s:%d UDP=%v: match=%v", ipv6, tc.src, tc.sp, tc.dst, tc.dp, tc.udp, got)
			}
		}
	}
}

func TestConnectionPacketSelectionValidationAndNanoseconds(t *testing.T) {
	base := url.Values{"srcIP": {"192.0.2.1"}, "dstIP": {"192.0.2.2"}, "srcPort": {"12345"}, "dstPort": {"443"}, "protocol": {"TCP"}, "startNs": {"1700000000000000001"}, "endNs": {"1700000000000000003"}}
	s, err := parseConnectionPacketSelection(base)
	if err != nil {
		t.Fatal(err)
	}
	for delta := int64(0); delta <= 4; delta++ {
		if got := s.contains(gopacket.CaptureInfo{Timestamp: time.Unix(0, 1700000000000000000+delta)}); got != (delta >= 1 && delta <= 3) {
			t.Fatalf("delta=%d: %v", delta, got)
		}
	}
	for key, value := range map[string]string{"srcIP": "192.0.2.1 or host 192.0.2.3", "srcPort": "443 or port 22", "dstPort": "65536", "protocol": "icmp", "endNs": "1700000000000000000", "dstIP": "2001:db8::1"} {
		q, _ := url.ParseQuery(base.Encode())
		q.Set(key, value)
		if _, err := parseConnectionPacketSelection(q); err == nil {
			t.Fatalf("accepted %s=%s", key, value)
		}
	}
}
