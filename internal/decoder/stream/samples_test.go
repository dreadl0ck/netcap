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

package stream

import (
	"encoding/hex"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

// A traffic sample for one protocol.
//
// Samples are byte literals rather than captures on purpose: .gitignore's
// unanchored "*.pcap" leaves 5 of the repo's ~3,990 capture files tracked, so a
// corpus-driven matrix silently skips on a clean checkout and in CI.
//
// The limit that follows is worth stating rather than hiding. A sample written
// from a decoder's own signature makes its diagonal cell vacuous: of course
// DNP3 matches bytes derived from dnp3.go. What the matrix is for is the
// off-diagonal — which *other* decoders also claim it — and that is not
// circular, because no sample is written with any other decoder in mind.
// Samples taken from real captures are marked; prefer adding more of those.
type sample struct {
	// decoder is the Name of the decoder that should claim this traffic.
	decoder string

	// port is the decoder's registered port, used to exercise the port pass.
	port int32

	// transport is the transport the sample would really arrive over.
	transport core.TransportProtocol

	// client and server are the two directions. Several decoders only inspect
	// one of them, so which side carries the bytes is part of the sample.
	client, server []byte

	// captured marks a sample lifted from a real capture rather than
	// constructed from the protocol specification.
	captured bool

	// wantVia is the path this sample should be claimed through when presented
	// on its own port. Everything is ViaPort except the decoders that are not
	// in the port map at all.
	wantVia string

	// takenOnPort records a decoder that currently claims this traffic even on
	// the protocol's own port, making the protocol unreachable. A defect, kept
	// here so the matrix stays a diff.
	takenOnPort string

	// note records provenance or anything surprising about the sample.
	note string
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad sample hex: " + err.Error())
	}

	return b
}

// --- builders shared with the per-decoder test packages -------------------

// tpktFrame wraps a payload in a TPKT (RFC 1006) header.
func tpktFrame(payload []byte) []byte {
	total := 4 + len(payload)

	return append([]byte{0x03, 0x00, byte(total >> 8), byte(total)}, payload...)
}

// s7JobPDU builds a classic S7comm Job (protocol id 0x32, ROSCTR 1) behind a
// COTP Data Transfer header. Mirrors s7comm/s7comm_test.go.
func s7JobPDU(param []byte) []byte {
	cotp := []byte{0x02, 0xf0, 0x80}
	hdr := []byte{
		0x32, 0x01, // protocol id, ROSCTR = Job
		0x00, 0x00, // reserved
		0x00, 0x00, // pdu ref
		byte(len(param) >> 8), byte(len(param)), // parameter length
		0x00, 0x00, // data length
	}

	return tpktFrame(append(cotp, append(hdr, param...)...))
}

// mbapADU builds a Modbus MBAP header around a PDU. Mirrors modbus's wire().
func mbapADU(unit byte, pdu ...byte) []byte {
	length := len(pdu) + 1

	return append([]byte{0, 1, 0, 0, byte(length >> 8), byte(length), unit}, pdu...)
}

// tlsRecord wraps a body in a TLS record header.
func tlsRecord(typ byte, body []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

// tlsHello builds a handshake record carrying a ClientHello (1) or
// ServerHello (2). Mirrors tls/tls_records_test.go.
func tlsHello(typ byte) []byte {
	return tlsRecord(22, append([]byte{typ, 0, 0, 38, 3, 3}, make([]byte, 36)...))
}

// derMessage builds an ASN.1 application-tagged message with a definite length,
// as Kerberos sends over UDP.
func derMessage(tag byte, bodyLen int) []byte {
	msg := []byte{tag}

	switch {
	case bodyLen < 0x80:
		msg = append(msg, byte(bodyLen))
	case bodyLen < 0x100:
		msg = append(msg, 0x81, byte(bodyLen))
	default:
		msg = append(msg, 0x82, byte(bodyLen>>8), byte(bodyLen))
	}

	return append(msg, make([]byte, bodyLen)...)
}

// kerberosTCP prefixes a DER message with the 4-byte record mark.
func kerberosTCP(tag byte, bodyLen int) []byte {
	body := derMessage(tag, bodyLen)
	mark := len(body)

	return append([]byte{byte(mark >> 24), byte(mark >> 16), byte(mark >> 8), byte(mark)}, body...)
}

// dnp3SA builds a DNP3 frame carrying a Secure Authentication function code.
func dnp3SA(function byte) []byte {
	frame := []byte{
		0x05, 0x64, 0x1A, 0xC4, 0x03, 0x00, 0x04, 0x00, 0xC9, 0xB7,
		0xC1, 0xC1, function,
	}

	return append(frame, make([]byte, 20)...)
}

// enipSendRRData is the ENIP-encapsulated CIP request from cip/cip_test.go.
var enipSendRRData = []byte{
	0x6f, 0x00, // SendRRData
	0x22, 0x00, // length 34
	0x44, 0x55, 0x8b, 0x88, // session handle
	0x00, 0x00, 0x00, 0x00, // status
	0x51, 0xc9, 0x0e, 0x00, 0x20, 0xcc, 0xd7, 0x00, // sender context
	0x00, 0x00, 0x00, 0x00, // options
	0x00, 0x00, 0x00, 0x00, // interface handle
	0x0a, 0x00, // timeout
	0x02, 0x00, // item count
	0x00, 0x00, 0x00, 0x00, // null address item
	0xb2, 0x00, 0x16, 0x00, // unconnected data item, length 22
	0x52, 0x02, 0x20, 0x06, 0x24, 0x01, 0x05, 0x9d,
	0x10, 0x00, 0x4b, 0x02, 0x20, 0x67, 0x24, 0x01,
	0x07, 0x3d, 0xf3, 0x45, 0xa3, 0x1b,
}

// samples is one entry per registered decoder.
//
// A decoder with no entry is a hole in the matrix, which TestEveryDecoderHasASample
// reports.
func samples() []sample {
	return []sample{
		{
			decoder: "FTP", port: 21, transport: core.TCP,
			client: []byte("USER anonymous\r\n"),
			server: []byte("220 ProFTPD Server ready\r\n"),
		},
		{
			decoder: "SSH", port: 22, transport: core.TCP,
			client: []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			server: []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		},
		{
			decoder: "SMTP", port: 25, transport: core.TCP,
			client: []byte("EHLO client.example.com\r\n"),
			server: []byte("220 mail.example.com ESMTP Postfix SMTP ready\r\n"),
		},
		{
			decoder: "TACACS", port: 49, transport: core.TCP,
			// Version 0xC0, type authentication, seq 1, plus a body.
			client: append([]byte{0xC0, 0x01, 0x01, 0x00, 0, 0, 0, 1, 0, 0, 0, 12}, make([]byte, 12)...),
			note:   "version nibble 0xC is the entire signature",
		},
		{
			decoder: "HTTP", port: 80, transport: core.TCP,
			client: []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			server: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
		},
		{
			decoder: "Kerberos", port: 88, transport: core.TCP,
			client: kerberosTCP(0x6a, 300), // AS-REQ
			server: kerberosTCP(0x6b, 300), // AS-REP
		},
		{
			decoder: "S7Comm", port: 102, transport: core.TCP,
			client: s7JobPDU([]byte{0x04, 0x00}), // ReadVar
			note:   "composed from s7comm/s7comm_test.go helpers",
		},
		{
			decoder: "POP3", port: 110, transport: core.TCP,
			client: []byte("USER alice\r\n"),
			server: []byte("+OK POP server ready\r\n"),
		},
		{
			decoder: "DCERPC", port: 135, transport: core.TCP,
			// v5.0, packet type 11 (Bind), flags, drep, frag length.
			client: append([]byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00}, make([]byte, 62)...),
		},
		{
			decoder: "IMAP", port: 143, transport: core.TCP,
			client: []byte("A001 CAPABILITY\r\n"),
			server: []byte("* OK IMAP4rev1 Service Ready\r\n"),
		},
		{
			decoder: "BGP", port: 179, transport: core.TCP,
			// 16-byte marker, length 29, type 1 (OPEN).
			client: append(append(make([]byte, 0, 29), bgpMarkerBytes()...), 0x00, 0x1d, 0x01, 0x04, 0xfd, 0xe8, 0x00, 0xb4, 0xc0, 0x00, 0x02, 0x01, 0x00),
		},
		{
			decoder: "TLSCertificate", port: 443, transport: core.TCP,
			client: tlsHello(1),
			server: tlsHello(2),
			note:   "TLS CanDecode depends on RecordDecoder.Writer; the test pins it",
		},
		{
			decoder: "SMB", port: 445, transport: core.TCP,
			// NetBIOS session header then the SMB2 signature.
			client: append([]byte{0x00, 0x00, 0x00, 0x48}, append([]byte("\xFESMB"), make([]byte, 60)...)...),
		},
		{
			decoder: "Modbus", port: 502, transport: core.TCP,
			client: mbapADU(1, 0x03, 0x00, 0x01, 0x00, 0x01), // read holding registers
			note:   "MBAP + FC3, validated by canDecodeModbus's full parse",
		},
		{
			decoder: "Syslog", port: 514, transport: core.UDP,
			client: []byte("<134>Oct 11 22:14:15 host app: message\n"),
		},
		{
			decoder: "IPP", port: 631, transport: core.TCP,
			client: []byte("POST /ipp/print HTTP/1.1\r\nContent-Type: application/ipp\r\n\r\n"),
		},
		{
			decoder: "SOCKS", port: 1080, transport: core.TCP,
			client: []byte{0x05, 0x01, 0x00},
			server: []byte{0x05, 0x00},
		},
		{
			decoder: "MQTTSN", port: 1883, transport: core.UDP,
			// length 14, CONNECT, flags, protocol id, duration, client id.
			client: append([]byte{0x0e, 0x04, 0x04, 0x01, 0x00, 0x1e}, []byte("clientid")...),
		},
		{
			decoder: "CIP", port: 2222, transport: core.TCP,
			client:   enipSendRRData,
			captured: true,
			note:     "from cip/cip_test.go sampleENIPCIPRequest",
		},
		{
			decoder: "IEC62351", port: 2404, transport: core.TCP,
			client: dnp3SA(0x20), // AUTHENTICATE_REQ
			note:   "DNP3 Secure Authentication, the branch iec62351 legitimately owns",
		},
		{
			decoder: "RDP", port: 3389, transport: core.TCP,
			// TPKT + X.224 Connection Request + the mstshash cookie.
			client: tpktFrame(append([]byte{0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00},
				[]byte("Cookie: mstshash=user\r\n")...)),
		},
		{
			decoder: "OPCUA", port: 4840, transport: core.TCP,
			// HELF + little-endian message size.
			client: append([]byte("HELF"), append([]byte{0x20, 0x00, 0x00, 0x00}, make([]byte, 24)...)...),
		},
		{
			decoder: "IRC", port: 6667, transport: core.TCP,
			client: []byte("NICK nick\r\nUSER u 0 * :real\r\n"),
			server: []byte(":irc.example.net 001 nick :Welcome to the network\r\n"),
		},
		{
			decoder: "Protobuf", port: 9090, transport: core.TCP,
			// field 1 varint, field 2 length-delimited string.
			client: append([]byte{0x08, 0x96, 0x01, 0x12, 0x07}, []byte("testing")...),
		},
		{
			decoder: "Zabbix", port: 10050, transport: core.TCP,
			client: append([]byte("ZBXD\x01"), append([]byte{0x0d, 0, 0, 0, 0, 0, 0, 0}, []byte("agent.ping")...)...),
		},
		{
			decoder: "DNP3", port: 20000, transport: core.TCP,
			client:   hexBytes("05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b"),
			captured: true,
			note:     "real select frame with a genuine CRC, tests/ICS-pcap/DNP3",
		},
		{
			decoder: "PROFINET", port: 34964, transport: core.TCP,
			// DCE/RPC v4, packet type 0 (Request), 24-byte header then body.
			client: append([]byte{0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00}, make([]byte, 32)...),
		},
		{
			decoder: "BACnetIP", port: 47808, transport: core.UDP,
			// BVLC type 0x81, function 0x0a (Original-Unicast-NPDU), length 12.
			client: append([]byte{0x81, 0x0a, 0x00, 0x0c}, make([]byte, 8)...),
		},
		{
			decoder: "QUICClientHello", port: 443, transport: core.UDP,
			client:   hexBytes("c000000001" + "0805" + "0102030405060708" + "00" + "4000"),
			captured: true,
			wantVia: ViaUDPList,
			note: "not in the port map at all: 443 is TLS over TCP. Reached through the UDP-only list, " +
				"which now competes in the scan rather than running after it",
		},
	}
}

// bgpMarkerBytes is BGP's 16-octet all-ones marker.
func bgpMarkerBytes() []byte {
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xFF
	}

	return marker
}
