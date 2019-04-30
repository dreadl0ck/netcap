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

package types

import (
	"encoding/hex"
	"strconv"
)

func (t TLSClientHello) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Type",
		"Version",
		"MessageLen",
		"HandshakeType",
		"HandshakeLen",
		"HandshakeVersion",
		"Random",
		"SessionIDLen",
		"SessionID",
		"CipherSuiteLen",
		"ExtensionLen",
		"SNI",
		"OSCP",
		"CipherSuites",
		"CompressMethods",
		"SignatureAlgs",
		"SupportedGroups",
		"SupportedPoints",
		"ALPNs",
		"Ja3",
		"SrcIP",
		"DstIP",
		"SrcMAC",
		"DstMAC",
		"SrcPort",
		"DstPort",
	})
}

func (t TLSClientHello) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(t.Timestamp),
		formatInt32(t.Type),
		formatInt32(t.Version),
		formatInt32(t.MessageLen),
		formatInt32(t.HandshakeType),
		strconv.FormatUint(uint64(t.HandshakeLen), 10),
		formatInt32(t.HandshakeVersion),
		hex.EncodeToString(t.Random),
		strconv.FormatUint(uint64(t.SessionIDLen), 10),
		hex.EncodeToString(t.SessionID),
		formatInt32(t.CipherSuiteLen),
		formatInt32(t.ExtensionLen),
		t.SNI,
		strconv.FormatBool(t.OSCP),
		joinInts(t.CipherSuites),
		joinInts(t.CompressMethods),
		joinInts(t.SignatureAlgs),
		joinInts(t.SupportedGroups),
		joinInts(t.SupportedPoints),
		join(t.ALPNs...),
		t.Ja3,
		t.SrcIP,
		t.DstIP,
		t.SrcMAC,
		t.DstMAC,
		formatInt32(t.SrcPort),
		formatInt32(t.DstPort),
	})
}

func (f TLSClientHello) NetcapTimestamp() string {
	return f.Timestamp
}

func (u TLSClientHello) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}
