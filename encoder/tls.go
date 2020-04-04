/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"strconv"

	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/tlsx"
	"github.com/golang/protobuf/proto"
)

// ExtractTLSHandShake extracts a TLS HandShake from a TCP Packet
func ExtractTLSHandShake(tcp *layers.TCP) (*tlsx.ClientHello, bool) {

	if tcp.SYN {
		// Connection setup
	} else if tcp.FIN {
		// Connection teardown
	} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
		// Acknowledgement packet
	} else if tcp.RST {
		// Unexpected packet
	} else {

		// invalid length, this is not handled by the tsx package
		// bail out otherwise there will be a panic
		if len(tcp.LayerPayload()) < 6 {
			return nil, false
		}

		// data packet
		var (
			hello = tlsx.ClientHello{}
			err   = hello.Unmarshal(tcp.LayerPayload())
		)

		switch err {
		case nil:
		case tlsx.ErrHandshakeWrongType:
			return nil, false
		default:
			// Log.WithError(err).Error("failed to read Client Hello")
			// Log.Debug("Raw Client Hello:", tcp.LayerPayload())
			return nil, false
		}

		return &hello, true
	}
	return nil, false
}

var tlsEncoder = CreateCustomEncoder(types.Type_NC_TLSClientHello, "TLS", nil, func(p gopacket.Packet) proto.Message {

	if tl := p.TransportLayer(); tl != nil {
		if tl.LayerType() == layers.LayerTypeTCP {
			tcp := tl.(*layers.TCP)

			// TLS ? extract clientHello
			if hello, ok := ExtractTLSHandShake(tcp); ok {

				var (
					cipherSuites    = make([]int32, len(hello.CipherSuites))
					compressMethods = make([]int32, len(hello.CompressMethods))
					signatureAlgs   = make([]int32, len(hello.SignatureAlgs))
					supportedGroups = make([]int32, len(hello.SupportedGroups))
					supportedPoints = make([]int32, len(hello.SupportedPoints))
					extensions      = make([]int32, len(hello.Extensions))
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
					srcPort, _ = strconv.Atoi(p.TransportLayer().TransportFlow().Src().String())
					dstPort, _ = strconv.Atoi(p.TransportLayer().TransportFlow().Src().String())
				)

				return &types.TLSClientHello{
					Timestamp:        utils.TimeToString(p.Metadata().Timestamp),
					Type:             int32(hello.Type),
					Version:          int32(hello.Version),
					MessageLen:       int32(hello.MessageLen),
					HandshakeType:    int32(hello.HandshakeType),
					HandshakeLen:     uint32(hello.HandshakeLen),
					HandshakeVersion: int32(hello.HandshakeVersion),
					Random:           hello.Random,
					SessionIDLen:     uint32(hello.SessionIDLen),
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
					Ja3:              ja3.DigestHexPacket(p),
					SrcIP:            p.NetworkLayer().NetworkFlow().Src().String(),
					DstIP:            p.NetworkLayer().NetworkFlow().Dst().String(),
					SrcMAC:           p.LinkLayer().LinkFlow().Src().String(),
					DstMAC:           p.LinkLayer().LinkFlow().Dst().String(),
					SrcPort:          int32(srcPort),
					DstPort:          int32(dstPort),
					Extensions:       extensions,
				}
			}
		}
	}
	return nil
}, nil)
