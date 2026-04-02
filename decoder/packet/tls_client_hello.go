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

package packet

import (
	"encoding/binary"
	"slices"

	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/ja4"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

// GREASE (Generate Random Extensions And Sustain Extensibility) values
// These are intentionally invalid values used by browsers to test server tolerance
// Reference: RFC 8701
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// isGreaseValue checks if a value is a GREASE value
func isGreaseValue(v uint16) bool {
	return greaseValues[v]
}

// hasGreaseExtensions checks if any extensions are GREASE values
func hasGreaseExtensions(extensions []uint16) bool {
	return slices.ContainsFunc(extensions, isGreaseValue)
}

// hasGreaseCipherSuites checks if any cipher suites are GREASE values
func hasGreaseCipherSuites(cipherSuites []tlsx.CipherSuite) bool {
	for _, cs := range cipherSuites {
		if isGreaseValue(uint16(cs)) {
			return true
		}
	}
	return false
}

// isSuspiciousCipherOrder checks for unusual cipher suite ordering
// Legitimate browsers typically list strong ciphers first
func isSuspiciousCipherOrder(cipherSuites []tlsx.CipherSuite) bool {
	if len(cipherSuites) < 2 {
		return false
	}

	// Check if weak/old ciphers appear before strong modern ciphers
	// TLS_AES_128_GCM_SHA256 (0x1301) and TLS_AES_256_GCM_SHA384 (0x1302) are TLS 1.3 ciphers
	// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) is a strong TLS 1.2 cipher

	strongCiphers := map[uint16]bool{
		0x1301: true, // TLS_AES_128_GCM_SHA256
		0x1302: true, // TLS_AES_256_GCM_SHA384
		0x1303: true, // TLS_CHACHA20_POLY1305_SHA256
		0xc02f: true, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc030: true, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xc02b: true, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc02c: true, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	}

	weakCiphers := map[uint16]bool{
		0x000a: true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x002f: true, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035: true, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x003c: true, // TLS_RSA_WITH_AES_128_CBC_SHA256
		0x003d: true, // TLS_RSA_WITH_AES_256_CBC_SHA256
		0x009c: true, // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x009d: true, // TLS_RSA_WITH_AES_256_GCM_SHA384
	}

	foundWeakFirst := false
	for _, cs := range cipherSuites {
		csVal := uint16(cs)
		if isGreaseValue(csVal) {
			continue
		}
		if weakCiphers[csVal] {
			foundWeakFirst = true
		}
		if strongCiphers[csVal] && foundWeakFirst {
			// Found a strong cipher after a weak one - suspicious
			return true
		}
	}

	return false
}

// Known malware JA4 fingerprints
// TODO: Populate with JA4 fingerprints once databases become available
var knownMalwareJA4 = map[string]string{}

var tlsClientHelloDecoder = newPacketDecoder(
	types.Type_NC_TLSClientHello,
	"TLSClientHello",
	"The client hello from a Transport Layer Security handshake",
	nil,
	func(p gopacket.Packet) proto.Message {
		hello := tlsx.GetClientHello(p)
		if hello != nil {

			var (
				cipherSuites    = make([]int32, len(hello.CipherSuites))
				compressMethods = make([]int32, len(hello.CompressMethods))
				signatureAlgs   = make([]int32, len(hello.SignatureAlgs))
				supportedGroups = make([]int32, len(hello.SupportedGroups))
				supportedPoints = make([]int32, len(hello.SupportedPoints))
				extensions      = make([]int32, len(hello.AllExtensions))
			)
			for i, v := range hello.CipherSuites {
				cipherSuites[i] = int32(v)
			}
			for i, v := range hello.CompressMethods {
				compressMethods[i] = int32(v)
			}
			for i, v := range hello.SignatureAlgs {
				signatureAlgs[i] = int32(v)
			}
			for i, v := range hello.SupportedGroups {
				supportedGroups[i] = int32(v)
			}
			for i, v := range hello.SupportedPoints {
				supportedPoints[i] = int32(v)
			}
			for i, v := range hello.AllExtensions {
				extensions[i] = int32(v)
			}

			var (
				srcPort, dstPort int
				srcMac, dstMac   string
				srcIP, dstIP     string
			)

			if ll := p.LinkLayer(); ll != nil {
				if len(ll.LinkFlow().Src().Raw()) > 0 {
					srcMac = ll.LinkFlow().Src().String()
				}
				if len(ll.LinkFlow().Dst().Raw()) > 0 {
					dstMac = ll.LinkFlow().Dst().String()
				}
			}

			if nl := p.NetworkLayer(); nl != nil {
				if len(nl.NetworkFlow().Src().Raw()) > 0 {
					srcIP = p.NetworkLayer().NetworkFlow().Src().String()
				}
				if len(nl.NetworkFlow().Dst().Raw()) > 0 {
					dstIP = p.NetworkLayer().NetworkFlow().Dst().String()
				}
			}

			if tl := p.TransportLayer(); tl != nil {
				if len(tl.TransportFlow().Src().Raw()) >= 2 {
					srcPort = int(binary.BigEndian.Uint16(p.TransportLayer().TransportFlow().Src().Raw()))
				}
				if len(tl.TransportFlow().Dst().Raw()) >= 2 {
					dstPort = int(binary.BigEndian.Uint16(p.TransportLayer().TransportFlow().Dst().Raw()))
				}
			}

			// Check for GREASE extensions (legitimate browsers typically use these)
			hasGrease := hasGreaseExtensions(hello.AllExtensions) || hasGreaseCipherSuites(hello.CipherSuites)

			// Check for suspicious cipher ordering
			suspiciousCipherOrder := isSuspiciousCipherOrder(hello.CipherSuites)

			// Compute JA4 fingerprint
			ja4CipherSuites := make([]uint16, len(hello.CipherSuites))
			for i, cs := range hello.CipherSuites {
				ja4CipherSuites[i] = uint16(cs)
			}

			// Convert signature algorithms to uint16 for JA4
			ja4SignatureAlgs := make([]uint16, len(hello.SignatureAlgs))
			for i, sa := range hello.SignatureAlgs {
				ja4SignatureAlgs[i] = uint16(sa)
			}

			// Get the highest supported TLS version from the supported_versions extension
			// This is parsed by tlsx v1.2.0+ and provides accurate TLS 1.3 detection
			var supportedVers uint16
			if len(hello.SupportedVersions) > 0 {
				// Find the highest non-GREASE version advertised
				for _, v := range hello.SupportedVersions {
					vers := uint16(v)
					if !isGreaseValue(vers) && vers > supportedVers {
						supportedVers = vers
					}
				}
			}
			ja4Fingerprint := ja4.ComputeJA4(&ja4.ClientHelloData{
				Version:             uint16(hello.Version),
				CipherSuites:        ja4CipherSuites,
				Extensions:          hello.AllExtensions,
				SNI:                 hello.SNI,
				ALPNs:               hello.ALPNs,
				SupportedVers:       supportedVers,
				IsQUIC:              false, // TCP/TLS connection
				SignatureAlgorithms: ja4SignatureAlgs,
			})

			// Check for known malware JA4 fingerprints (local hardcoded list)
			var isKnownMalware bool
			var threatCategory string
			if category, found := knownMalwareJA4[ja4Fingerprint]; found {
				isKnownMalware = true
				threatCategory = category
			}

			// Also check JA4+ database for additional threat intelligence
			ja4Description := resolvers.LookupJA4(ja4Fingerprint)
			if ja4Description != "" {
				if threatCategory == "" {
					threatCategory = ja4Description
				} else {
					threatCategory += "; " + ja4Description
				}
			}

			return &types.TLSClientHello{
				Timestamp:        p.Metadata().Timestamp.UnixNano(),
				Type:             int32(hello.Type),
				Version:          int32(hello.Version),
				MessageLen:       int32(hello.MessageLen),
				HandshakeType:    int32(hello.HandshakeType),
				HandshakeLen:     hello.HandshakeLen,
				HandshakeVersion: int32(hello.HandshakeVersion),
				Random:           hello.Random,
				SessionIDLen:     hello.SessionIDLen,
				SessionID:        hello.SessionID,
				CipherSuiteLen:   int32(hello.CipherSuiteLen),
				ExtensionLen:     int32(hello.ExtensionLen),
				SNI:              hello.SNI,
				OSCP:             hello.OSCP,
				CipherSuites:     cipherSuites,
				CompressMethods:  compressMethods,
				SignatureAlgs:    signatureAlgs,
				SupportedGroups:  supportedGroups,
				SupportedPoints:  supportedPoints,
				ALPNs:            hello.ALPNs,
				SrcIP:            srcIP,
				DstIP:            dstIP,
				SrcMAC:           srcMac,
				DstMAC:           dstMac,
				SrcPort:          int32(srcPort),
				DstPort:          int32(dstPort),
				Extensions:       extensions,
				// Threat intelligence fields
				IsKnownMalware:          isKnownMalware,
				ThreatCategory:          threatCategory,
				HasGreaseExtensions:     hasGrease,
				IsSuspiciousCipherOrder: suspiciousCipherOrder,
				ExtensionCount:          int32(len(hello.AllExtensions)),
				// JA4 fingerprint
				Ja4:            ja4Fingerprint,
				Ja4Description: ja4Description,
			}
		}

		return nil
	},
	nil,
)
