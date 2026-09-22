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

	"github.com/dreadl0ck/netcap/types"
)

func TestSTUNDecoder_BindingRequest(t *testing.T) {
	// Build a STUN Binding Request (RFC 5389)
	// Message Type: 0x0001 (Binding Request)
	// Length: 0
	// Magic Cookie: 0x2112A442
	// Transaction ID: 12 bytes
	stunPayload := []byte{
		0x00, 0x01, // Message Type: Binding Request
		0x00, 0x00, // Message Length: 0
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		// Transaction ID (12 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{10, 0, 0, 1},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 3478,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(stunPayload))
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	result := stunDecoder.Handler(p)
	if result == nil {
		t.Fatal("Expected STUN record, got nil")
	}

	stun, ok := result.(*types.STUN)
	if !ok {
		t.Fatalf("Expected *types.STUN, got %T", result)
	}

	if stun.MessageClass != "Request" {
		t.Errorf("Expected MessageClass 'Request', got %q", stun.MessageClass)
	}
	if stun.Method != "Binding" {
		t.Errorf("Expected Method 'Binding', got %q", stun.Method)
	}
	if !stun.IsRFC5389 {
		t.Error("Expected IsRFC5389 to be true")
	}
}

func TestSTUNDecoder_WithXORMappedAddress(t *testing.T) {
	// STUN Binding Success Response with XOR-MAPPED-ADDRESS
	// XOR-MAPPED-ADDRESS: family=IPv4, port=0x1234 XOR 0x2112 = 0x3326, IP=192.168.1.1 XOR 0x2112A442
	xorPort := uint16(0x1234) ^ 0x2112
	xorIP := []byte{
		192 ^ 0x21, 168 ^ 0x12, 1 ^ 0xA4, 1 ^ 0x42,
	}

	stunPayload := []byte{
		0x01, 0x01, // Message Type: Binding Success Response
		0x00, 0x0c, // Message Length: 12 (one attribute)
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, // Transaction ID
		// XOR-MAPPED-ADDRESS attribute
		0x00, 0x20, // Type: XOR-MAPPED-ADDRESS
		0x00, 0x08, // Length: 8
		0x00, 0x01, // Reserved + Family (IPv4)
		byte(xorPort >> 8), byte(xorPort & 0xFF), // XOR'd port
		xorIP[0], xorIP[1], xorIP[2], xorIP[3], // XOR'd IP
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{192, 168, 1, 100},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 3478,
		DstPort: 12345,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(stunPayload))

	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	result := stunDecoder.Handler(p)
	if result == nil {
		t.Fatal("Expected STUN record, got nil")
	}

	stun := result.(*types.STUN)
	if stun.MappedAddress == "" {
		t.Error("Expected MappedAddress to be set")
	}
	t.Logf("MappedAddress: %s", stun.MappedAddress)

	if stun.MessageClass != "SuccessResponse" {
		t.Errorf("Expected MessageClass 'SuccessResponse', got %q", stun.MessageClass)
	}
}

func TestSTUNDecoder_NotSTUN(t *testing.T) {
	// Random UDP payload without STUN magic cookie
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{10, 0, 0, 1},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 3478,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))

	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	result := stunDecoder.Handler(p)
	if result != nil {
		t.Error("Expected nil for non-STUN packet, got a record")
	}
}
