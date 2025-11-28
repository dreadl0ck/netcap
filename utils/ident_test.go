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

package utils

import (
	"log"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestCreateFlowIdentFromLayerFlows(t *testing.T) {
	netFlow, err := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}),
	)
	if err != nil {
		log.Fatal(err)
	}

	trans, err := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(3456),
		layers.NewTCPPortEndpoint(80),
	)
	if err != nil {
		log.Fatal(err)
	}

	ident := CreateFlowIdentFromLayerFlows(netFlow, trans)
	if ident != "1.2.3.4:3456->5.6.7.8:80" {
		t.Fatal("unexpected ident", ident)
	}
}

func BenchmarkFlowIdentFromLayerFlows(b *testing.B) {
	netFlow, err := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}),
	)
	if err != nil {
		log.Fatal(err)
	}

	trans, err := gopacket.FlowFromEndpoints(
		layers.NewTCPPortEndpoint(3456),
		layers.NewTCPPortEndpoint(80),
	)
	if err != nil {
		log.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		CreateFlowIdentFromLayerFlows(netFlow, trans)
	}
}

func TestCreateFlowIdent(t *testing.T) {
	ident := CreateFlowIdent("127.0.0.1", "43532", "127.0.0.1", "80")
	if ident != "127.0.0.1:43532->127.0.0.1:80" {
		t.Fatal("unexpected ident", ident)
	}
}

func BenchmarkCreateFlowIdent(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		CreateFlowIdent("127.0.0.1", "43532", "127.0.0.1", "80")
	}
}

func TestReverseFlowIdent(t *testing.T) {
	res := ReverseFlowIdent("192.168.1.47:53032->165.227.109.154:80")
	if res != "165.227.109.154:80->192.168.1.47:53032" {
		t.Fatal("got", res, "expected: 165.227.109.154:80->192.168.1.47:53032")
	}
}

func BenchmarkReverseFlowIdent(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ReverseFlowIdent("192.168.1.47:53032->165.227.109.154:80")
	}
}

func TestParseFlowIdent(t *testing.T) {
	srcIP, srcPort, dstIP, dstPort := ParseFlowIdent("192.168.1.47:53032->165.227.109.154:80")
	if srcIP != "192.168.1.47" {
		t.Fatal("got srcIP", srcIP, "expected: 192.168.1.47")
	}
	if srcPort != "53032" {
		t.Fatal("got srcPort", srcPort, "expected: 53032")
	}
	if dstIP != "165.227.109.154" {
		t.Fatal("got dstIP", dstIP, "expected: 165.227.109.154")
	}
	if dstPort != "80" {
		t.Fatal("got dstPort", dstPort, "expected: 80")
	}
}

func BenchmarkParseFlowIdent(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ParseFlowIdent("192.168.1.47:53032->165.227.109.154:80")
	}
}
