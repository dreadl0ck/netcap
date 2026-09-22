/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package injection

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// PacketBuilder provides utilities for constructing network packets.
type PacketBuilder struct {
	// Default TTL for IP packets
	DefaultTTL uint8

	// Default window size for TCP packets
	DefaultWindow uint16
}

// NewPacketBuilder creates a new packet builder with default settings.
func NewPacketBuilder() *PacketBuilder {
	return &PacketBuilder{
		DefaultTTL:    64,
		DefaultWindow: 65535,
	}
}

// TCPPacketConfig holds configuration for building TCP packets.
type TCPPacketConfig struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   TCPFlags
	Window  uint16
	Payload []byte
	TTL     uint8
}

// TCPFlags represents TCP control flags.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

// BuildTCPPacket constructs a complete TCP packet.
func (pb *PacketBuilder) BuildTCPPacket(config TCPPacketConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Set defaults
	if config.TTL == 0 {
		config.TTL = pb.DefaultTTL
	}
	if config.Window == 0 {
		config.Window = pb.DefaultWindow
	}

	// Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       config.SrcMAC,
		DstMAC:       config.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Determine IP version
	isIPv6 := config.SrcIP.To4() == nil

	var ipLayer gopacket.NetworkLayer

	if isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ipv6 := &layers.IPv6{
			Version:    6,
			HopLimit:   config.TTL,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      config.SrcIP,
			DstIP:      config.DstIP,
		}
		ipLayer = ipv6
	} else {
		ipv4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      config.TTL,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    config.SrcIP.To4(),
			DstIP:    config.DstIP.To4(),
		}
		ipLayer = ipv4
	}

	// TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(config.SrcPort),
		DstPort: layers.TCPPort(config.DstPort),
		Seq:     config.Seq,
		Ack:     config.Ack,
		Window:  config.Window,
		SYN:     config.Flags.SYN,
		ACK:     config.Flags.ACK,
		FIN:     config.Flags.FIN,
		RST:     config.Flags.RST,
		PSH:     config.Flags.PSH,
		URG:     config.Flags.URG,
		ECE:     config.Flags.ECE,
		CWR:     config.Flags.CWR,
		NS:      config.Flags.NS,
	}
	tcp.SetNetworkLayerForChecksum(ipLayer)

	// Serialize
	var serializeLayers []gopacket.SerializableLayer
	serializeLayers = append(serializeLayers, eth)

	if isIPv6 {
		serializeLayers = append(serializeLayers, ipLayer.(*layers.IPv6))
	} else {
		serializeLayers = append(serializeLayers, ipLayer.(*layers.IPv4))
	}

	serializeLayers = append(serializeLayers, tcp)

	if len(config.Payload) > 0 {
		serializeLayers = append(serializeLayers, gopacket.Payload(config.Payload))
	}

	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		return nil, fmt.Errorf("failed to serialize TCP packet: %w", err)
	}

	return buf.Bytes(), nil
}

// BuildTCPRSTPacket creates a TCP RST packet.
func (pb *PacketBuilder) BuildTCPRSTPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32) ([]byte, error) {
	return pb.BuildTCPPacket(TCPPacketConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		Flags:   TCPFlags{RST: true, ACK: true},
		Window:  0,
	})
}

// BuildTCPSYNPacket creates a TCP SYN packet.
func (pb *PacketBuilder) BuildTCPSYNPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) ([]byte, error) {
	return pb.BuildTCPPacket(TCPPacketConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Flags:   TCPFlags{SYN: true},
	})
}

// BuildTCPSYNACKPacket creates a TCP SYN-ACK packet.
func (pb *PacketBuilder) BuildTCPSYNACKPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32) ([]byte, error) {
	return pb.BuildTCPPacket(TCPPacketConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		Flags:   TCPFlags{SYN: true, ACK: true},
	})
}

// UDPPacketConfig holds configuration for building UDP packets.
type UDPPacketConfig struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Payload []byte
	TTL     uint8
}

// BuildUDPPacket constructs a complete UDP packet.
func (pb *PacketBuilder) BuildUDPPacket(config UDPPacketConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if config.TTL == 0 {
		config.TTL = pb.DefaultTTL
	}

	eth := &layers.Ethernet{
		SrcMAC:       config.SrcMAC,
		DstMAC:       config.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	isIPv6 := config.SrcIP.To4() == nil
	var ipLayer gopacket.NetworkLayer

	if isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ipv6 := &layers.IPv6{
			Version:    6,
			HopLimit:   config.TTL,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      config.SrcIP,
			DstIP:      config.DstIP,
		}
		ipLayer = ipv6
	} else {
		ipv4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      config.TTL,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    config.SrcIP.To4(),
			DstIP:    config.DstIP.To4(),
		}
		ipLayer = ipv4
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(config.SrcPort),
		DstPort: layers.UDPPort(config.DstPort),
	}
	udp.SetNetworkLayerForChecksum(ipLayer)

	var serializeLayers []gopacket.SerializableLayer
	serializeLayers = append(serializeLayers, eth)

	if isIPv6 {
		serializeLayers = append(serializeLayers, ipLayer.(*layers.IPv6))
	} else {
		serializeLayers = append(serializeLayers, ipLayer.(*layers.IPv4))
	}

	serializeLayers = append(serializeLayers, udp)

	if len(config.Payload) > 0 {
		serializeLayers = append(serializeLayers, gopacket.Payload(config.Payload))
	}

	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		return nil, fmt.Errorf("failed to serialize UDP packet: %w", err)
	}

	return buf.Bytes(), nil
}

// DNSQueryConfig holds configuration for building DNS query packets.
type DNSQueryConfig struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16 // Usually 53
	QueryID   uint16
	QueryName string
	QueryType layers.DNSType
	TTL       uint8
}

// BuildDNSQueryPacket constructs a DNS query packet.
func (pb *PacketBuilder) BuildDNSQueryPacket(config DNSQueryConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if config.TTL == 0 {
		config.TTL = pb.DefaultTTL
	}
	if config.DstPort == 0 {
		config.DstPort = 53
	}
	if config.QueryType == 0 {
		config.QueryType = layers.DNSTypeA
	}

	eth := &layers.Ethernet{
		SrcMAC:       config.SrcMAC,
		DstMAC:       config.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      config.TTL,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    config.SrcIP.To4(),
		DstIP:    config.DstIP.To4(),
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(config.SrcPort),
		DstPort: layers.UDPPort(config.DstPort),
	}
	udp.SetNetworkLayerForChecksum(ipv4)

	dns := &layers.DNS{
		ID:     config.QueryID,
		QR:     false, // Query
		OpCode: layers.DNSOpCodeQuery,
		RD:     true, // Recursion desired
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(config.QueryName),
				Type:  config.QueryType,
				Class: layers.DNSClassIN,
			},
		},
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, ipv4, udp, dns); err != nil {
		return nil, fmt.Errorf("failed to serialize DNS query: %w", err)
	}

	return buf.Bytes(), nil
}

// DNSResponseConfig holds configuration for building DNS response packets.
type DNSResponseConfig struct {
	SrcMAC      net.HardwareAddr
	DstMAC      net.HardwareAddr
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16 // Usually 53
	DstPort     uint16
	QueryID     uint16
	QueryName   string
	QueryType   layers.DNSType
	ResponseIP  net.IP
	ResponseTTL uint32
	TTL         uint8
}

// BuildDNSResponsePacket constructs a DNS response packet.
func (pb *PacketBuilder) BuildDNSResponsePacket(config DNSResponseConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if config.TTL == 0 {
		config.TTL = pb.DefaultTTL
	}
	if config.SrcPort == 0 {
		config.SrcPort = 53
	}
	if config.QueryType == 0 {
		config.QueryType = layers.DNSTypeA
	}
	if config.ResponseTTL == 0 {
		config.ResponseTTL = 300
	}

	eth := &layers.Ethernet{
		SrcMAC:       config.SrcMAC,
		DstMAC:       config.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      config.TTL,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    config.SrcIP.To4(),
		DstIP:    config.DstIP.To4(),
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(config.SrcPort),
		DstPort: layers.UDPPort(config.DstPort),
	}
	udp.SetNetworkLayerForChecksum(ipv4)

	dns := &layers.DNS{
		ID:           config.QueryID,
		QR:           true, // Response
		OpCode:       layers.DNSOpCodeQuery,
		AA:           true, // Authoritative
		RD:           true,
		RA:           true,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(config.QueryName),
				Type:  config.QueryType,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(config.QueryName),
				Type:  config.QueryType,
				Class: layers.DNSClassIN,
				TTL:   config.ResponseTTL,
				IP:    config.ResponseIP,
			},
		},
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, ipv4, udp, dns); err != nil {
		return nil, fmt.Errorf("failed to serialize DNS response: %w", err)
	}

	return buf.Bytes(), nil
}

// ARPPacketConfig holds configuration for building ARP packets.
type ARPPacketConfig struct {
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	SenderMAC    net.HardwareAddr
	SenderIP     net.IP
	TargetMAC    net.HardwareAddr
	TargetIP     net.IP
	Operation    uint16 // layers.ARPRequest or layers.ARPReply
	IsGratuitous bool
}

// BuildARPPacket constructs an ARP packet.
func (pb *PacketBuilder) BuildARPPacket(config ARPPacketConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// For gratuitous ARP, sender and target are the same
	if config.IsGratuitous {
		config.TargetIP = config.SenderIP
		config.TargetMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		config.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		config.Operation = layers.ARPReply
	}

	eth := &layers.Ethernet{
		SrcMAC:       config.SrcMAC,
		DstMAC:       config.DstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         config.Operation,
		SourceHwAddress:   config.SenderMAC,
		SourceProtAddress: config.SenderIP.To4(),
		DstHwAddress:      config.TargetMAC,
		DstProtAddress:    config.TargetIP.To4(),
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, fmt.Errorf("failed to serialize ARP packet: %w", err)
	}

	return buf.Bytes(), nil
}

// BuildARPRequestPacket creates an ARP request packet.
func (pb *PacketBuilder) BuildARPRequestPacket(senderMAC net.HardwareAddr, senderIP, targetIP net.IP) ([]byte, error) {
	return pb.BuildARPPacket(ARPPacketConfig{
		SrcMAC:    senderMAC,
		DstMAC:    net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		SenderMAC: senderMAC,
		SenderIP:  senderIP,
		TargetMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unknown
		TargetIP:  targetIP,
		Operation: layers.ARPRequest,
	})
}

// BuildARPReplyPacket creates an ARP reply packet.
func (pb *PacketBuilder) BuildARPReplyPacket(senderMAC, targetMAC net.HardwareAddr, senderIP, targetIP net.IP) ([]byte, error) {
	return pb.BuildARPPacket(ARPPacketConfig{
		SrcMAC:    senderMAC,
		DstMAC:    targetMAC,
		SenderMAC: senderMAC,
		SenderIP:  senderIP,
		TargetMAC: targetMAC,
		TargetIP:  targetIP,
		Operation: layers.ARPReply,
	})
}

// BuildGratuitousARPPacket creates a gratuitous ARP packet.
func (pb *PacketBuilder) BuildGratuitousARPPacket(mac net.HardwareAddr, ip net.IP) ([]byte, error) {
	return pb.BuildARPPacket(ARPPacketConfig{
		SrcMAC:       mac,
		SenderMAC:    mac,
		SenderIP:     ip,
		IsGratuitous: true,
	})
}

// ICMPPacketConfig holds configuration for building ICMP packets.
type ICMPPacketConfig struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	Type    layers.ICMPv4TypeCode
	ID      uint16
	Seq     uint16
	Payload []byte
	TTL     uint8
}

// BuildICMPPacket constructs an ICMPv4 packet.
func (pb *PacketBuilder) BuildICMPPacket(config ICMPPacketConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if config.TTL == 0 {
		config.TTL = pb.DefaultTTL
	}

	eth := &layers.Ethernet{
		SrcMAC:       config.SrcMAC,
		DstMAC:       config.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      config.TTL,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    config.SrcIP.To4(),
		DstIP:    config.DstIP.To4(),
	}

	icmp := &layers.ICMPv4{
		TypeCode: config.Type,
		Id:       config.ID,
		Seq:      config.Seq,
	}

	var serializeLayers []gopacket.SerializableLayer
	serializeLayers = append(serializeLayers, eth, ipv4, icmp)

	if len(config.Payload) > 0 {
		serializeLayers = append(serializeLayers, gopacket.Payload(config.Payload))
	}

	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		return nil, fmt.Errorf("failed to serialize ICMP packet: %w", err)
	}

	return buf.Bytes(), nil
}

// BuildICMPEchoRequest creates an ICMP echo request (ping) packet.
func (pb *PacketBuilder) BuildICMPEchoRequest(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq uint16, payload []byte) ([]byte, error) {
	return pb.BuildICMPPacket(ICMPPacketConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Type:    layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		ID:      id,
		Seq:     seq,
		Payload: payload,
	})
}

// BuildICMPEchoReply creates an ICMP echo reply packet.
func (pb *PacketBuilder) BuildICMPEchoReply(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq uint16, payload []byte) ([]byte, error) {
	return pb.BuildICMPPacket(ICMPPacketConfig{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Type:    layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		ID:      id,
		Seq:     seq,
		Payload: payload,
	})
}
