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

package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// SharedKey is the default TACACS+ shared secret used for decryption.
// Override this for your environment.
var SharedKey = "John3.16"

type tacacsReader struct {
	conversation *core.ConversationInfo
}

// New returns a new TACACS+ reader.
func (t *tacacsReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &tacacsReader{
		conversation: conversation,
	}
}

// TACACS+ type names
var tacacsTypeNames = map[int]string{
	1: "Authentication",
	2: "Authorization",
	3: "Accounting",
}

// TACACS+ authentication action names
var authenActionNames = map[byte]string{
	0x01: "LOGIN",
	0x02: "CHPASS",
	0x03: "SENDPASS",
	0x04: "SENDAUTH",
}

// TACACS+ authentication status names
var authenStatusNames = map[byte]string{
	0x01: "PASS",
	0x02: "FAIL",
	0x03: "GETDATA",
	0x04: "GETUSER",
	0x05: "GETPASS",
	0x06: "RESTART",
	0x07: "ERROR",
	0x15: "FOLLOW",
}

const tacacsHeaderLen = 12

// Decode parses TACACS+ messages from the stream.
func (t *tacacsReader) Decode() {
	if Decoder.Writer == nil {
		tacacsLog.Error("TACACS Decoder.Writer is nil")
		return
	}

	for _, d := range t.conversation.Data {
		raw := d.Raw()
		if len(raw) < tacacsHeaderLen {
			continue
		}

		records := t.parseTACACSPackets(raw)
		for _, rec := range records {
			rec.SrcIP = t.conversation.ClientIP
			rec.DstIP = t.conversation.ServerIP
			rec.SrcPort = int32(t.conversation.ClientPort)
			rec.DstPort = int32(t.conversation.ServerPort)
			rec.Flow = t.conversation.Ident
			rec.Timestamp = t.conversation.FirstClientPacket.UnixNano()

			err := Decoder.Writer.Write(rec)
			if err != nil {
				tacacsLog.Error("failed to write tacacs record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}
	}
}

func (t *tacacsReader) parseTACACSPackets(data []byte) []*types.TACACS {
	var results []*types.TACACS

	offset := 0
	for offset+tacacsHeaderLen <= len(data) {
		pkt := data[offset:]

		// Validate major version
		if pkt[0]&0xF0 != 0xC0 {
			break
		}

		version := pkt[0]
		majorVer := int32(version >> 4)
		minorVer := int32(version & 0x0F)
		pktType := pkt[1]
		seqNo := pkt[2]
		flags := pkt[3]
		sessionID := binary.BigEndian.Uint32(pkt[4:8])
		bodyLen := binary.BigEndian.Uint32(pkt[8:12])

		totalLen := tacacsHeaderLen + int(bodyLen)
		if offset+totalLen > len(data) {
			break
		}

		typeName := tacacsTypeNames[int(pktType)]
		if typeName == "" {
			typeName = "Unknown"
		}

		rec := &types.TACACS{
			VersionMajor:   majorVer,
			VersionMinor:   minorVer,
			Type:           int32(pktType),
			TypeName:       typeName,
			SequenceNumber: int32(seqNo),
			Flags:          int32(flags),
			SessionID:      int32(sessionID),
			Length:         int32(bodyLen),
		}

		if bodyLen > 0 {
			body := make([]byte, bodyLen)
			copy(body, pkt[tacacsHeaderLen:totalLen])

			// TAC_PLUS_UNENCRYPTED_FLAG is bit 0
			if flags&0x01 == 0 && SharedKey != "" {
				// Body is encrypted, decrypt with XOR pad
				t.decryptBody(body, version, seqNo, sessionID)
			}

			// Parse body based on type
			t.parseBody(rec, pktType, seqNo, body)
		}

		results = append(results, rec)
		offset += totalLen
	}

	return results
}

// decryptBody decrypts the TACACS+ body using the XOR pad method.
// pad = MD5(session_id + key + version + seq_no) + MD5(session_id + key + version + seq_no + pad1) + ...
func (t *tacacsReader) decryptBody(body []byte, version, seqNo byte, sessionID uint32) {
	key := []byte(SharedKey)
	sidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sidBytes, sessionID)

	var pad []byte
	var prevHash []byte

	for len(pad) < len(body) {
		h := md5.New()
		h.Write(sidBytes)
		h.Write(key)
		h.Write([]byte{version})
		h.Write([]byte{seqNo})
		if prevHash != nil {
			h.Write(prevHash)
		}
		prevHash = h.Sum(nil)
		pad = append(pad, prevHash...)
	}

	for i := range body {
		body[i] ^= pad[i]
	}
}

func (t *tacacsReader) parseBody(rec *types.TACACS, pktType, seqNo byte, body []byte) {
	switch pktType {
	case 1: // Authentication
		if seqNo == 1 {
			// Authentication START
			t.parseAuthenStart(rec, body)
		} else if seqNo%2 == 0 {
			// Authentication REPLY (even sequence numbers are server responses)
			t.parseAuthenReply(rec, body)
		}
	}
}

func (t *tacacsReader) parseAuthenStart(rec *types.TACACS, body []byte) {
	if len(body) < 8 {
		return
	}

	action := body[0]
	// privLvl := body[1]
	// authenType := body[2]
	// service := body[3]
	userLen := int(body[4])
	portLen := int(body[5])
	remAddrLen := int(body[6])
	// dataLen := int(body[7])

	offset := 8

	if actionName, ok := authenActionNames[action]; ok {
		rec.Action = actionName
	}

	if offset+userLen <= len(body) {
		rec.User = string(body[offset : offset+userLen])
		offset += userLen
	}

	// Skip port field
	if offset+portLen > len(body) {
		return
	}
	offset += portLen

	if offset+remAddrLen <= len(body) {
		rec.RemoteAddr = string(body[offset : offset+remAddrLen])
	}
}

func (t *tacacsReader) parseAuthenReply(rec *types.TACACS, body []byte) {
	if len(body) < 6 {
		return
	}

	status := body[0]
	// flags := body[1]
	// serverMsgLen := binary.BigEndian.Uint16(body[2:4])
	// dataLen := binary.BigEndian.Uint16(body[4:6])

	rec.Status = int32(status)
	if statusName, ok := authenStatusNames[status]; ok {
		rec.StatusName = statusName
	}
}
