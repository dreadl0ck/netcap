/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package packet

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestLLMNRDecoder_BasicQuery(t *testing.T) {
	// Build a minimal LLMNR query packet (DNS format on UDP 5355)
	// DNS header: ID=0x1234, flags=0x0000 (query), QDCOUNT=1, rest=0
	// Question: name="test", type=A(1), class=IN(1)
	dnsPayload := []byte{
		0x12, 0x34, // ID
		0x00, 0x00, // Flags (standard query)
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// Question: "test" type A class IN
		0x04, 't', 'e', 's', 't', 0x00, // name
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
	}

	// Build gopacket with Ethernet + IPv4 + UDP layers
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{224, 0, 0, 252},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 5355,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(dnsPayload))
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	result := llmnrDecoder.Handler(p)
	if result == nil {
		t.Fatal("Expected LLMNR record, got nil")
	}

	t.Logf("LLMNR record: %+v", result)
}

func TestLLMNRDecoder_NonLLMNRPort(t *testing.T) {
	// DNS payload on port 53 (not 5355) should not match
	dnsPayload := []byte{
		0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{8, 8, 8, 8},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(dnsPayload))

	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	result := llmnrDecoder.Handler(p)
	if result != nil {
		t.Error("Expected nil for non-LLMNR port, got a record")
	}
}
