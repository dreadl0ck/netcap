/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"

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
	for _, ext := range extensions {
		if isGreaseValue(ext) {
			return true
		}
	}
	return false
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

// computeJa3Normalized computes Ja3 hash with GREASE values removed
func computeJa3Normalized(hello *tlsx.ClientHelloBasic) string {
	// Filter out GREASE values from cipher suites
	var filteredCipherSuites []string
	for _, cs := range hello.CipherSuites {
		if !isGreaseValue(uint16(cs)) {
			filteredCipherSuites = append(filteredCipherSuites, strconv.Itoa(int(cs)))
		}
	}

	// Filter out GREASE values from extensions
	var filteredExtensions []string
	for _, ext := range hello.AllExtensions {
		if !isGreaseValue(ext) {
			filteredExtensions = append(filteredExtensions, strconv.Itoa(int(ext)))
		}
	}

	// Filter out GREASE values from supported groups
	var filteredGroups []string
	for _, g := range hello.SupportedGroups {
		if !isGreaseValue(uint16(g)) {
			filteredGroups = append(filteredGroups, strconv.Itoa(int(g)))
		}
	}

	// Build normalized Ja3 string: Version,CipherSuites,Extensions,SupportedGroups,SupportedPoints
	ja3String := strconv.Itoa(int(hello.Version)) + "," +
		strings.Join(filteredCipherSuites, "-") + "," +
		strings.Join(filteredExtensions, "-") + "," +
		strings.Join(filteredGroups, "-") + ","

	// Add supported points (no GREASE values for EC point formats)
	var points []string
	for _, p := range hello.SupportedPoints {
		points = append(points, strconv.Itoa(int(p)))
	}
	ja3String += strings.Join(points, "-")

	return ja3.BareToDigestHex([]byte(ja3String))
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

// Known malware Ja3 fingerprints (subset of common ones)
// These should be loaded from a database in production
var knownMalwareJa3 = map[string]string{
	"51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike",
	"72a589da586844d7f0818ce684948eea": "Metasploit",
	"e7d705a3286e19ea42f587b344ee6865": "Emotet",
	"4d7a28d6f2263ed61de88ca66eb011e3": "TrickBot",
	"6734f37431670b3ab4292b8f60f29984": "Dridex",
	"232f15d1c94b7c4f9dcc09dc19b46eb5": "IcedID",
	"a0e9f5d64349fb13191bc781f81f42e1": "QakBot",
}

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

			// Compute Ja3 hash
			ja3Hash := ja3.DigestHex(&hello.ClientHelloBasic)

			// Threat intelligence: lookup Ja3 fingerprint
			ja3Lookup := resolvers.LookupJa3(ja3Hash)
			var ja3Descriptions []string
			if ja3Lookup != "" {
				ja3Descriptions = append(ja3Descriptions, ja3Lookup)
			}

			// Check for known malware fingerprints
			var isKnownMalware bool
			var threatCategory string
			if category, found := knownMalwareJa3[ja3Hash]; found {
				isKnownMalware = true
				threatCategory = category
			}

			// Check for GREASE extensions (legitimate browsers typically use these)
			hasGrease := hasGreaseExtensions(hello.AllExtensions) || hasGreaseCipherSuites(hello.CipherSuites)

			// Compute normalized Ja3 (without GREASE values)
			ja3Normalized := computeJa3Normalized(&hello.ClientHelloBasic)

			// Check for suspicious cipher ordering
			suspiciousCipherOrder := isSuspiciousCipherOrder(hello.CipherSuites)

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
				Ja3:              ja3Hash,
				SrcIP:            srcIP,
				DstIP:            dstIP,
				SrcMAC:           srcMac,
				DstMAC:           dstMac,
				SrcPort:          int32(srcPort),
				DstPort:          int32(dstPort),
				Extensions:       extensions,
				// Threat intelligence fields
				Ja3Descriptions:        ja3Descriptions,
				IsKnownMalware:         isKnownMalware,
				ThreatCategory:         threatCategory,
				HasGreaseExtensions:    hasGrease,
				Ja3Normalized:          ja3Normalized,
				IsSuspiciousCipherOrder: suspiciousCipherOrder,
				ExtensionCount:         int32(len(hello.AllExtensions)),
			}
		}

		return nil
	},
	nil,
)
