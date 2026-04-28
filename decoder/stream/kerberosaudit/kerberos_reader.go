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
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
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

	for _, d := range k.conversation.Data {
		raw := d.Raw()
		if len(raw) < 2 {
			continue
		}

		records := k.parseKerberosMessages(raw)
		for _, rec := range records {
			rec.SrcIP = k.conversation.ClientIP
			rec.DstIP = k.conversation.ServerIP
			rec.SrcPort = int32(k.conversation.ClientPort)
			rec.DstPort = int32(k.conversation.ServerPort)
			rec.Flow = k.conversation.Ident
			rec.Timestamp = k.conversation.FirstClientPacket.UnixNano()

			err := Decoder.Writer.Write(rec)
			if err != nil {
				kerberosLog.Error("failed to write kerberos record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
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
	// Parse the outer application-tagged wrapper
	var inner asn1.RawValue
	rest, err := asn1.Unmarshal(data, &inner)
	_ = rest
	if err != nil {
		return
	}

	// The inner content should be a SEQUENCE
	var seq asn1.RawValue
	remaining := inner.Bytes
	for len(remaining) > 0 {
		remaining, err = asn1.Unmarshal(remaining, &seq)
		if err != nil {
			return
		}

		// Context-specific tagged fields inside the Kerberos message
		if seq.Class == asn1.ClassContextSpecific {
			switch seq.Tag {
			case 7: // realm in AS-REQ/TGS-REQ (crealm in replies)
				var realm string
				if _, err2 := asn1.Unmarshal(seq.Bytes, &realm); err2 == nil {
					rec.Realm = realm
				}
			case 9: // crealm in AS-REP/TGS-REP
				var realm string
				if _, err2 := asn1.Unmarshal(seq.Bytes, &realm); err2 == nil {
					if rec.Realm == "" {
						rec.Realm = realm
					}
				}
			case 4: // cname (PrincipalName) in requests
				k.extractPrincipalName(seq.Bytes, rec, true)
			case 10: // cname in replies
				k.extractPrincipalName(seq.Bytes, rec, true)
			case 5: // sname (PrincipalName) in requests
				k.extractPrincipalName(seq.Bytes, rec, false)
			case 6: // error-code in KRB-ERROR
				var errCode int
				if _, err2 := asn1.Unmarshal(seq.Bytes, &errCode); err2 == nil {
					rec.ErrorCode = int32(errCode)
				}
			}
		}
	}
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
