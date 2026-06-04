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

//go:build fuzz

// Package-level fuzz harnesses for the packet decoders. These feed
// arbitrary bytes through gopacket's layer parser and then invoke the
// matching netcap layer->audit-record handler, asserting only that
// neither stage panics. They are gated behind the `fuzz` build tag so
// the default unit suite stays fast and deterministic.
//
// Run a single target with, e.g.:
//
//	go test -tags fuzz -run x -fuzz=FuzzDNSDecoder -fuzztime=30s ./decoder/packet/
package packet

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

// fuzzLayerDecoder drives a raw byte slice through gopacket's parser for
// the decoder's layer type and then through the netcap handler. The whole
// point is to surface panics (nil derefs, slice bounds, etc.) in the
// layer->record conversion path on malformed input.
func fuzzLayerDecoder(f *testing.F, dec *GoPacketDecoder, seeds ...[]byte) {
	f.Helper()

	// The DNS (and a few other) handlers read package-level conf; make
	// sure it is non-nil and exercises the entropy path.
	conf = decoderconfig.DefaultConfig
	conf.CalculateEntropy = true

	for _, s := range seeds {
		f.Add(s)
	}
	// A couple of always-present generic seeds.
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// gopacket.NewPacket itself must not panic on arbitrary bytes.
		p := gopacket.NewPacket(data, dec.Layer, gopacket.DecodeOptions{
			Lazy:   false,
			NoCopy: true,
		})
		layer := p.Layer(dec.Layer)
		if layer == nil {
			return
		}
		// The netcap handler must not panic on any successfully decoded
		// layer, regardless of how degenerate the field values are.
		_ = dec.Handler(layer, 0)
	})
}

func FuzzDNSDecoder(f *testing.F) {
	// Minimal DNS query for "a.com" as a seed.
	seed := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		0x01, 'a', 0x03, 'c', 'o', 'm', 0x00, // QNAME a.com
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	fuzzLayerDecoder(f, dnsDecoder, seed)
}

func FuzzDHCPv4Decoder(f *testing.F) {
	fuzzLayerDecoder(f, dhcpv4Decoder)
}

func FuzzDHCPv6Decoder(f *testing.F) {
	fuzzLayerDecoder(f, dhcpv6Decoder)
}

func FuzzGTPDecoder(f *testing.F) {
	fuzzLayerDecoder(f, gtpDecoder)
}

func FuzzGREDecoder(f *testing.F) {
	fuzzLayerDecoder(f, greDecoder)
}

func FuzzGeneveDecoder(f *testing.F) {
	fuzzLayerDecoder(f, geneveDecoder)
}

func FuzzVXLANDecoder(f *testing.F) {
	fuzzLayerDecoder(f, vxlanDecoder)
}

func FuzzSIPDecoder(f *testing.F) {
	fuzzLayerDecoder(f, sipDecoder)
}

func FuzzNTPDecoder(f *testing.F) {
	fuzzLayerDecoder(f, ntpDecoder)
}

func FuzzRADIUSDecoder(f *testing.F) {
	fuzzLayerDecoder(f, radiusDecoder)
}

func FuzzOSPFv2Decoder(f *testing.F) {
	fuzzLayerDecoder(f, ospfv2Decoder)
}

func FuzzOSPFv3Decoder(f *testing.F) {
	fuzzLayerDecoder(f, ospfv3Decoder)
}

func FuzzSCTPDecoder(f *testing.F) {
	fuzzLayerDecoder(f, sctpDecoder)
}

func FuzzICMPv6Decoder(f *testing.F) {
	fuzzLayerDecoder(f, icmpv6Decoder)
}

// FuzzEthernetDecoder is the broadest target: feeding bytes in as an
// Ethernet frame lets gopacket descend through the whole layer stack.
func FuzzEthernetDecoder(f *testing.F) {
	fuzzLayerDecoder(f, ethernetDecoder)
	_ = layers.LayerTypeEthernet // keep layers import in case seeds expand
}

// FuzzDNSNameHelpers exercises the pure string helpers that derive the
// DNS security-monitoring fields. They must never panic and must hold
// simple invariants on arbitrary UTF-8/byte input.
func FuzzDNSNameHelpers(f *testing.F) {
	for _, s := range []string{
		"", ".", "a", "a.com", "www.example.co.uk.", "..", "a..b",
		"xn--80ak6aa92e.com", "\x00\xff", "ÄÖÜ.test",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		// Entropy is always in [0, log2(len)] and never negative/NaN.
		ent := dnsQueryNameEntropy(name)
		if ent < 0 || ent != ent { // NaN check
			t.Fatalf("dnsQueryNameEntropy(%q) = %v, want >= 0 and not NaN", name, ent)
		}

		// extractTLD must return a substring that contains no dot.
		tld := extractTLD(name)
		for _, r := range tld {
			if r == '.' {
				t.Fatalf("extractTLD(%q) = %q contains a dot", name, tld)
			}
		}

		// countSubdomains is never negative.
		if n := countSubdomains(name); n < 0 {
			t.Fatalf("countSubdomains(%q) = %d, want >= 0", name, n)
		}
	})
}
