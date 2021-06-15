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

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

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
				srcMac = ll.LinkFlow().Src().String()
				dstMac = ll.LinkFlow().Dst().String()
			}

			if nl := p.NetworkLayer(); nl != nil {
				srcIP = p.NetworkLayer().NetworkFlow().Src().String()
				dstIP = p.NetworkLayer().NetworkFlow().Dst().String()
			}

			if tl := p.TransportLayer(); tl != nil {
				srcPort = int(binary.BigEndian.Uint16(p.TransportLayer().TransportFlow().Src().Raw()))
				dstPort = int(binary.BigEndian.Uint16(p.TransportLayer().TransportFlow().Dst().Raw()))
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
				Ja3:              ja3.DigestHex(&hello.ClientHelloBasic),
				SrcIP:            srcIP,
				DstIP:            dstIP,
				SrcMAC:           srcMac,
				DstMAC:           dstMac,
				SrcPort:          int32(srcPort),
				DstPort:          int32(dstPort),
				Extensions:       extensions,
			}
		}

		return nil
	},
	nil,
)
