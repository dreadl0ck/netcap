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

package kerberosaudit

import (
	"encoding/asn1"
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

type kerberosReader struct {
	conversation *core.ConversationInfo
}

// New returns a new kerberos reader.
func (k *kerberosReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &kerberosReader{
		conversation: conversation,
	}
}

// messageTypeNames maps Kerberos message type codes to human-readable names.
var messageTypeNames = map[int]string{
	10: "AS-REQ",
	11: "AS-REP",
	12: "TGS-REQ",
	13: "TGS-REP",
	14: "AP-REQ",
	15: "AP-REP",
	30: "KRB-ERROR",
}

// Decode parses Kerberos messages from the stream.
func (k *kerberosReader) Decode() {
	if Decoder.Writer == nil {
		kerberosLog.Error("Kerberos Decoder.Writer is nil")
		return
	}

	k.decodeMessages(func(rec *types.Kerberos, d core.DataFragment) {
		// Time and direction come from the fragment that carried the
		// bytes. Every record used to take FirstClientPacket and the
		// client's addresses, which collapses a session to one instant and
		// records a server reply as though the client had sent it.
		rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort = k.conversation.Endpoints(d)
		rec.Flow = k.conversation.Ident
		rec.CommunityID = k.conversation.CommunityID
		rec.Timestamp = core.FragmentTime(d)

		err := Decoder.Writer.Write(rec)
		if err != nil {
			kerberosLog.Error("failed to write kerberos record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

// TCP record marks are directional; never join UDP datagrams or cross a gap.
func (k *kerberosReader) decodeMessages(emit func(*types.Kerberos, core.DataFragment)) {
	type pending struct {
		bytes   []byte
		first   core.DataFragment
		stopped bool
	}
	states := [2]pending{}
	for _, d := range k.conversation.Data {
		if d == nil {
			continue
		}
		if k.conversation.ClientData == nil && k.conversation.ServerData == nil && d.Context() == nil {
			for _, rec := range k.parseKerberosMessages(d.Raw()) {
				emit(rec, d)
			}
			continue
		}
		index := 0
		if d.Direction() == reassembly.TCPDirServerToClient {
			index = 1
		}
		s := &states[index]
		if frag, ok := d.(*core.StreamData); ok && frag.SkippedBytes != 0 {
			s.bytes = nil
			s.stopped = true
		}
		if s.stopped {
			continue
		}
		if len(s.bytes) == 0 {
			s.first = d
		}
		if len(s.bytes)+len(d.Raw()) > 4<<20 {
			s.stopped = true
			s.bytes = nil
			continue
		}
		s.bytes = append(s.bytes, d.Raw()...)
		for len(s.bytes) >= 4 {
			n := int(binary.BigEndian.Uint32(s.bytes))
			if n < 2 || n > 1<<20 {
				s.stopped = true
				s.bytes = nil
				break
			}
			if len(s.bytes) < n+4 {
				break
			}
			for _, rec := range k.parseKerberosMessages(s.bytes[4 : 4+n]) {
				emit(rec, s.first)
			}
			s.bytes = s.bytes[n+4:]
			s.first = d
		}
	}
}

func (k *kerberosReader) parseKerberosMessages(data []byte) []*types.Kerberos {
	var results []*types.Kerberos

	offset := 0
	for offset < len(data) {
		remaining := data[offset:]
		if len(remaining) < 2 {
			break
		}

		asn1Data := remaining

		// If we see a non-ASN.1 application tag, check for 4-byte TCP record mark
		if !isKerberosAppTag(remaining[0]) {
			if len(remaining) >= 5 && isKerberosAppTag(remaining[4]) {
				asn1Data = remaining[4:]
				offset += 4
			} else {
				break
			}
		}

		rec := k.parseSingleMessage(asn1Data)
		if rec != nil {
			results = append(results, rec)
		}

		// Advance past this ASN.1 structure
		consumed := k.asn1Length(asn1Data)
		if consumed <= 0 {
			break
		}
		offset += consumed
	}

	return results
}

func (k *kerberosReader) parseSingleMessage(data []byte) *types.Kerberos {
	if len(data) < 2 {
		return nil
	}
	if n, ok := derMessageSize(data); !ok || n != len(data) || !isKerberosAppTag(data[0]) {
		return nil
	}

	// Extract the application tag number
	tag := data[0]
	if tag < 0x60 {
		return nil
	}
	tagNum := int(tag & 0x1f)

	msgTypeName, ok := messageTypeNames[tagNum]
	if !ok {
		msgTypeName = "Unknown"
	}

	rec := &types.Kerberos{
		MessageType:     msgTypeName,
		MessageTypeCode: int32(tagNum),
	}

	// Try to extract realm and principal names from the ASN.1 structure
	k.extractKerberosDetails(data, rec)

	return rec
}

// extractKerberosDetails attempts to parse ASN.1 structure for realm and principal names.
func (k *kerberosReader) extractKerberosDetails(data []byte, rec *types.Kerberos) {
	var inner asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &inner); err != nil || len(rest) != 0 || inner.Class != asn1.ClassApplication {
		return
	}
	fields := kerberosFields(inner.Bytes)
	var cname, sname, realm []byte
	switch rec.MessageTypeCode {
	case 10, 12:
		body := kerberosFields(fields[4]) // KDC-REQ.req-body
		cname, sname, realm = body[1], body[3], body[2]
		var typesList []int
		if _, err := asn1.Unmarshal(body[8], &typesList); err == nil {
			for _, n := range typesList {
				rec.RequestedEncryptionTypes = append(rec.RequestedEncryptionTypes, int32(n))
			}
		}
	case 11, 13:
		cname, realm = fields[4], fields[3]
		ticket := kerberosTicket(fields[5])
		sname = ticket[2]
		setEncryptionType(fields[6], rec)
	case 14:
		ticket := kerberosTicket(fields[3])
		sname, realm = ticket[2], ticket[1]
		setEncryptionType(ticket[3], rec)
	case 30:
		cname, sname, realm = fields[8], fields[10], fields[7]
		if len(realm) == 0 {
			realm = fields[9]
		}
		var code int
		if _, err := asn1.Unmarshal(fields[6], &code); err == nil {
			rec.ErrorCode = int32(code)
		}
		_, _ = asn1.Unmarshal(fields[11], &rec.ErrorMessage)
	}
	_, _ = asn1.Unmarshal(realm, &rec.Realm)
	k.extractPrincipalName(cname, rec, true)
	k.extractPrincipalName(sname, rec, false)
}

func setEncryptionType(data []byte, rec *types.Kerberos) {
	fields := kerberosFields(data)
	var n int
	if _, err := asn1.Unmarshal(fields[0], &n); err != nil {
		return
	}
	rec.EncryptionType = int32(n)
	rec.EncryptionTypeName = map[int]string{1: "des-cbc-crc", 3: "des-cbc-md5", 16: "des3-cbc-sha1", 17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96", 19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192", 23: "rc4-hmac"}[n]
}

func kerberosFields(data []byte) map[int][]byte {
	fields := make(map[int][]byte)
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &seq); err != nil || len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return fields
	}
	for b := seq.Bytes; len(b) > 0; {
		var f asn1.RawValue
		rest, err := asn1.Unmarshal(b, &f)
		if err != nil || f.Class != asn1.ClassContextSpecific {
			return nil
		}
		if _, duplicate := fields[f.Tag]; duplicate {
			return nil
		}
		fields[f.Tag] = f.Bytes
		b = rest
	}
	return fields
}

func kerberosTicket(data []byte) map[int][]byte {
	var ticket asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &ticket); err != nil || len(rest) != 0 || ticket.Class != asn1.ClassApplication || ticket.Tag != 1 {
		return nil
	}
	return kerberosFields(ticket.Bytes)
}

// extractPrincipalName parses a PrincipalName ASN.1 structure.
func (k *kerberosReader) extractPrincipalName(data []byte, rec *types.Kerberos, isClient bool) {
	// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
	var seq asn1.RawValue
	remaining := data
	var err error

	// Parse the SEQUENCE wrapper
	remaining, err = asn1.Unmarshal(remaining, &seq)
	if err != nil {
		return
	}

	// Parse inside the SEQUENCE
	inner := seq.Bytes
	if seq.Tag == asn1.TagSequence && seq.Class == asn1.ClassUniversal {
		inner = seq.Bytes
	}

	var nameStr string
	for len(inner) > 0 {
		var field asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &field)
		if err != nil {
			return
		}

		if field.Class == asn1.ClassContextSpecific && field.Tag == 1 {
			// name-string: SEQUENCE OF KerberosString
			var names asn1.RawValue
			_, err2 := asn1.Unmarshal(field.Bytes, &names)
			if err2 != nil {
				continue
			}
			nameData := names.Bytes
			for len(nameData) > 0 {
				var s string
				nameData, err = asn1.Unmarshal(nameData, &s)
				if err != nil {
					break
				}
				if nameStr != "" {
					nameStr += "/"
				}
				nameStr += s
			}
		}
	}

	if nameStr != "" {
		if isClient {
			rec.ClientName = nameStr
		} else {
			rec.ServerName = nameStr
		}
	}
}

// asn1Length returns the total length of an ASN.1 TLV structure.
func (k *kerberosReader) asn1Length(data []byte) int {
	if len(data) < 2 {
		return 0
	}

	lenByte := data[1]
	if lenByte < 0x80 {
		return 2 + int(lenByte)
	}

	numLenBytes := int(lenByte & 0x7f)
	if len(data) < 2+numLenBytes {
		return 0
	}

	length := 0
	for i := 0; i < numLenBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}

	total := 2 + numLenBytes + length
	if total < 0 || total > len(data) {
		return 0
	}

	return total
}
