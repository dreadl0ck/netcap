// Package helpers provides utilities for generating synthetic test PCAPs
package helpers

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// TCPFlags represents TCP flag bits
type TCPFlags uint8

// TCP flag constants
const (
	TCPFlagFin TCPFlags = 1 << iota
	TCPFlagSyn
	TCPFlagRst
	TCPFlagPsh
	TCPFlagAck
	TCPFlagUrg
)

// PcapConfig contains configuration for PCAP generation
type PcapConfig struct {
	Filename string
	LinkType layers.LinkType
	SnapLen  uint32
}

// PacketBuilder helps build test packets
type PacketBuilder struct {
	config PcapConfig
	writer *pcapgo.Writer
	file   *os.File
}

// NewPacketBuilder creates a new packet builder
func NewPacketBuilder(config PcapConfig) (*PacketBuilder, error) {
	if config.SnapLen == 0 {
		config.SnapLen = 65535
	}

	if config.LinkType == 0 {
		config.LinkType = layers.LinkTypeEthernet
	}

	file, err := os.Create(config.Filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(config.SnapLen, config.LinkType); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write PCAP header: %w", err)
	}

	return &PacketBuilder{
		config: config,
		writer: writer,
		file:   file,
	}, nil
}

// Close closes the PCAP file
func (pb *PacketBuilder) Close() error {
	return pb.file.Close()
}

// WritePacket writes a packet to the PCAP file
func (pb *PacketBuilder) WritePacket(data []byte) error {
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}

	return pb.writer.WritePacket(ci, data)
}

// BuildEthernetIPv4TCPPacket builds a simple Ethernet/IPv4/TCP packet
func (pb *PacketBuilder) BuildEthernetIPv4TCPPacket(
	srcMAC, dstMAC string,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags TCPFlags,
	payload []byte,
) ([]byte, error) {

	// Parse MAC addresses
	srcMACAddr, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid source MAC: %w", err)
	}
	dstMACAddr, err := net.ParseMAC(dstMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid destination MAC: %w", err)
	}

	// Parse IP addresses
	srcIPAddr := net.ParseIP(srcIP)
	dstIPAddr := net.ParseIP(dstIP)

	// Build layers
	eth := &layers.Ethernet{
		SrcMAC:       srcMACAddr,
		DstMAC:       dstMACAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIPAddr,
		DstIP:    dstIPAddr,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		Window:  65535,
	}

	// Set TCP flags
	if flags&TCPFlagSyn != 0 {
		tcp.SYN = true
	}
	if flags&TCPFlagAck != 0 {
		tcp.ACK = true
	}
	if flags&TCPFlagFin != 0 {
		tcp.FIN = true
	}
	if flags&TCPFlagRst != 0 {
		tcp.RST = true
	}
	if flags&TCPFlagPsh != 0 {
		tcp.PSH = true
	}

	// Set network layer for TCP checksum calculation
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	return buf.Bytes(), nil
}

// GenerateTCPHandshake generates a complete TCP 3-way handshake
func GenerateTCPHandshake(filename string, srcIP, dstIP string, srcPort, dstPort uint16) error {
	config := PcapConfig{
		Filename: filename,
		LinkType: layers.LinkTypeEthernet,
		SnapLen:  65535,
	}

	pb, err := NewPacketBuilder(config)
	if err != nil {
		return err
	}
	defer pb.Close()

	srcMAC := "aa:bb:cc:dd:ee:01"
	dstMAC := "aa:bb:cc:dd:ee:02"

	// SYN
	syn, err := pb.BuildEthernetIPv4TCPPacket(
		srcMAC, dstMAC,
		srcIP, dstIP,
		srcPort, dstPort,
		1000, 0,
		TCPFlagSyn,
		nil,
	)
	if err != nil {
		return err
	}
	if err := pb.WritePacket(syn); err != nil {
		return err
	}

	// SYN-ACK
	synack, err := pb.BuildEthernetIPv4TCPPacket(
		dstMAC, srcMAC,
		dstIP, srcIP,
		dstPort, srcPort,
		2000, 1001,
		TCPFlagSyn|TCPFlagAck,
		nil,
	)
	if err != nil {
		return err
	}
	if err := pb.WritePacket(synack); err != nil {
		return err
	}

	// ACK
	ack, err := pb.BuildEthernetIPv4TCPPacket(
		srcMAC, dstMAC,
		srcIP, dstIP,
		srcPort, dstPort,
		1001, 2001,
		TCPFlagAck,
		nil,
	)
	if err != nil {
		return err
	}
	if err := pb.WritePacket(ack); err != nil {
		return err
	}

	return nil
}

// GenerateHTTPRequest generates a simple HTTP GET request in a PCAP
func GenerateHTTPRequest(filename string, host string) error {
	config := PcapConfig{
		Filename: filename,
		LinkType: layers.LinkTypeEthernet,
		SnapLen:  65535,
	}

	pb, err := NewPacketBuilder(config)
	if err != nil {
		return err
	}
	defer pb.Close()

	srcIP := "192.168.1.100"
	dstIP := "93.184.216.34" // example.com
	srcPort := uint16(54321)
	dstPort := uint16(80)
	srcMAC := "aa:bb:cc:dd:ee:01"
	dstMAC := "aa:bb:cc:dd:ee:02"

	// TCP handshake
	syn, _ := pb.BuildEthernetIPv4TCPPacket(srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, 1000, 0, TCPFlagSyn, nil)
	pb.WritePacket(syn)

	synack, _ := pb.BuildEthernetIPv4TCPPacket(dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort, 2000, 1001, TCPFlagSyn|TCPFlagAck, nil)
	pb.WritePacket(synack)

	ack, _ := pb.BuildEthernetIPv4TCPPacket(srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, 1001, 2001, TCPFlagAck, nil)
	pb.WritePacket(ack)

	// HTTP GET request
	httpPayload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: NetcapTest/1.0\r\n\r\n", host))
	httpPkt, err := pb.BuildEthernetIPv4TCPPacket(
		srcMAC, dstMAC,
		srcIP, dstIP,
		srcPort, dstPort,
		1001, 2001,
		TCPFlagPsh|TCPFlagAck,
		httpPayload,
	)
	if err != nil {
		return err
	}

	return pb.WritePacket(httpPkt)
}

// GenerateDNSQuery generates a DNS query/response pair
func GenerateDNSQuery(filename string, domain string) error {
	config := PcapConfig{
		Filename: filename,
		LinkType: layers.LinkTypeEthernet,
		SnapLen:  65535,
	}

	pb, err := NewPacketBuilder(config)
	if err != nil {
		return err
	}
	defer pb.Close()

	// TODO: Implement DNS packet generation
	// This would require constructing DNS layer with gopacket

	return nil
}
