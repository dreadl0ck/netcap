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

package collector

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestSymmetricFlowSharding(t *testing.T) {
	c := &Collector{
		numWorkers: 4,
	}

	// Helper to create a dummy packet
	createPacket := func(srcIP, dstIP net.IP, srcPort, dstPort int) gopacket.Packet {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
			Version:  4,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
		}
		tcp.SetNetworkLayerForChecksum(ip)
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
		if err != nil {
			t.Fatal(err)
		}
		return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	}

	t.Run("IPv4 TCP Symmetry", func(t *testing.T) {
		src := net.ParseIP("192.168.1.100")
		dst := net.ParseIP("1.1.1.1")

		// Forward: Client -> Server
		p1 := createPacket(src, dst, 12345, 80)
		if p1.NetworkLayer() == nil {
			t.Fatal("p1 NetworkLayer is nil")
		}
		idx1 := c.getSymmetricWorkerIndex(p1)

		// Reverse: Server -> Client
		p2 := createPacket(dst, src, 80, 12345)
		if p2.NetworkLayer() == nil {
			t.Fatal("p2 NetworkLayer is nil")
		}
		idx2 := c.getSymmetricWorkerIndex(p2)

		if idx1 != idx2 {
			t.Errorf("Expected same worker index for bidirectional flow, got %d and %d", idx1, idx2)
		}
	})

	t.Run("IPv6 Symmetry", func(t *testing.T) {
		src := net.ParseIP("2001:db8::1")
		dst := net.ParseIP("2001:db8::2")

		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip := &layers.IPv6{
			SrcIP:      src,
			DstIP:      dst,
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
		}
		udp := &layers.UDP{
			SrcPort: 53,
			DstPort: 12345,
		}
		// Set pseudo header for checksum calculation
		udp.SetNetworkLayerForChecksum(ip)

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err := gopacket.SerializeLayers(buffer, opts, eth, ip, udp)
		if err != nil {
			t.Fatal(err)
		}
		p1 := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		if p1.NetworkLayer() == nil {
			t.Fatal("p1 ipv6 NetworkLayer is nil")
		}

		// Reverse
		ipReverse := &layers.IPv6{
			SrcIP:      dst,
			DstIP:      src,
			NextHeader: layers.IPProtocolUDP,
			Version:    6,
		}
		udpReverse := &layers.UDP{
			SrcPort: 12345,
			DstPort: 53,
		}
		udpReverse.SetNetworkLayerForChecksum(ipReverse)

		buffer2 := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer2, opts, eth, ipReverse, udpReverse)
		if err != nil {
			t.Fatal(err)
		}
		p2 := gopacket.NewPacket(buffer2.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		if p2.NetworkLayer() == nil {
			t.Fatal("p2 ipv6 NetworkLayer is nil")
		}

		idx1 := c.getSymmetricWorkerIndex(p1)
		idx2 := c.getSymmetricWorkerIndex(p2)

		if idx1 != idx2 {
			t.Errorf("Expected same worker index for IPv6 bidirectional flow, got %d and %d", idx1, idx2)
		}
	})

	t.Run("Distribution", func(t *testing.T) {
		// Verify that we hit different workers for different flows
		counts := make(map[int]int)
		src := net.ParseIP("192.168.1.100")
		dst := net.ParseIP("1.1.1.1")

		for i := 0; i < 100; i++ {
			// Vary source port
			p := createPacket(src, dst, 10000+i, 80)
			idx := c.getSymmetricWorkerIndex(p)
			counts[idx]++
		}

		if len(counts) < 2 {
			t.Errorf("Poor distribution: packets mapped to only %d workers out of 4", len(counts))
		}
	})
}

func TestPacketDispatch(t *testing.T) {
	// Setup collector with buffered channels
	workers := make([]chan gopacket.Packet, 4)
	for i := 0; i < 4; i++ {
		workers[i] = make(chan gopacket.Packet, 10)
	}

	c := &Collector{
		numWorkers: 4,
		workers:    workers,
	}

	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")

	// Create flow packets
	// Flow 1: A->B
	p1 := createIPv4UDP(src, dst, 100, 200)
	// Flow 1: B->A
	p2 := createIPv4UDP(dst, src, 200, 100)

	// Determine expected worker
	expectedIdx := c.getSymmetricWorkerIndex(p1)

	// Dispatch
	c.handlePacket(p1)
	c.handlePacket(p2)

	// Verify both went to the same worker
	select {
	case <-workers[expectedIdx]:
		// Good, got p1
	default:
		t.Errorf("Packet 1 did not arrive at expected worker %d", expectedIdx)
	}

	select {
	case <-workers[expectedIdx]:
		// Good, got p2
	default:
		t.Errorf("Packet 2 did not arrive at expected worker %d", expectedIdx)
	}

	// Verify other workers are empty
	for i, w := range workers {
		if i != expectedIdx {
			select {
			case <-w:
				t.Errorf("Worker %d received packet unexpectedly", i)
			default:
				// Good
			}
		}
	}
}

func createIPv4UDP(src, dst net.IP, srcPort, dstPort int) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    src,
		DstIP:    dst,
		Protocol: layers.IPProtocolUDP,
		Version:  4,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, udp)
	if err != nil {
		panic(err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
