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

package dcerpc

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type dcerpcReader struct {
	conversation *core.ConversationInfo
}

// New returns a new DCE/RPC reader.
func (d *dcerpcReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &dcerpcReader{
		conversation: conversation,
	}
}

const dcerpcHeaderLen = 16

// packetTypeNames maps DCE/RPC packet type codes to human-readable names.
var packetTypeNames = map[int]string{
	0:  "Request",
	1:  "Ping",
	2:  "Response",
	3:  "Fault",
	4:  "Working",
	5:  "NoCall",
	6:  "Reject",
	7:  "Ack",
	8:  "CancelAck",
	9:  "Fack",
	10: "CancelAck",
	11: "Bind",
	12: "BindAck",
	13: "BindNak",
	14: "AlterContext",
	15: "AlterContextResp",
	16: "Shutdown",
	17: "CoCancel",
	18: "Orphaned",
}

// wellKnownInterfaces maps well-known DCE/RPC interface UUIDs to human-readable names.
var wellKnownInterfaces = map[string]string{
	"e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPM",
	"4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC",
	"12345778-1234-abcd-ef00-0123456789ab": "LSARPC",
	"12345678-1234-abcd-ef00-0123456789ab": "SPOOLSS",
	"338cd001-2244-31f1-aaaa-900038001003": "WINREG",
	"367abb81-9844-35f1-ad32-98f038001003": "SVCCTL",
	"86d35949-83c9-4044-b424-db363231fd0c": "ITaskSchedulerService",
	"12345778-1234-abcd-ef00-01234567cffb": "NETLOGON",
	"3919286a-b10c-11d0-9ba8-00c04fd92ef5": "DSSETUP",
	"e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DRSUAPI",
	"4fc742e0-4a10-11cf-8273-00aa004ae673": "DFSNM",
	"c681d488-d850-11d0-8c52-00c04fd90f7e": "EFSR",
}

// Decode parses DCE/RPC PDUs from the stream.
func (d *dcerpcReader) Decode() {
	if Decoder.Writer == nil {
		dcerpcLog.Error("DCERPC Decoder.Writer is nil")
		return
	}

	for _, fragment := range d.conversation.Data {
		raw := fragment.Raw()
		if len(raw) < dcerpcHeaderLen {
			continue
		}

		records := d.parseDCERPCPDUs(raw)
		for _, rec := range records {
			rec.SrcIP = d.conversation.ClientIP
			rec.DstIP = d.conversation.ServerIP
			rec.SrcPort = int32(d.conversation.ClientPort)
			rec.DstPort = int32(d.conversation.ServerPort)
			rec.Flow = d.conversation.Ident
			rec.Timestamp = d.conversation.FirstClientPacket.UnixNano()

			err := Decoder.Writer.Write(rec)
			if err != nil {
				dcerpcLog.Error("failed to write dcerpc record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}
	}
}

func (d *dcerpcReader) parseDCERPCPDUs(data []byte) []*types.DCERPC {
	var results []*types.DCERPC

	offset := 0
	for offset+dcerpcHeaderLen <= len(data) {
		pdu := data[offset:]

		// Validate version
		if pdu[0] != 5 || (pdu[1] != 0 && pdu[1] != 1) {
			break
		}

		pktType := int(pdu[2])
		if pktType > 19 {
			break
		}

		flags := pdu[3]

		// Data representation: byte order is in the first byte of data_rep
		// Bit 4 of data_rep[0]: 0=big-endian, 1=little-endian
		var byteOrder binary.ByteOrder = binary.LittleEndian
		if pdu[4]&0x10 == 0 {
			byteOrder = binary.BigEndian
		}

		fragLength := byteOrder.Uint16(pdu[8:10])
		// authLength := byteOrder.Uint16(pdu[10:12])
		callID := byteOrder.Uint32(pdu[12:16])

		if int(fragLength) < dcerpcHeaderLen || offset+int(fragLength) > len(data) {
			break
		}

		pktTypeName := packetTypeNames[pktType]
		if pktTypeName == "" {
			pktTypeName = "Unknown"
		}

		rec := &types.DCERPC{
			Version:        int32(pdu[0]),
			VersionMinor:   int32(pdu[1]),
			PacketType:     int32(pktType),
			PacketTypeName: pktTypeName,
			Flags:          int32(flags),
			FragLength:     int32(fragLength),
			CallID:         int32(callID),
		}

		// Extract additional fields based on packet type
		pduBody := pdu[dcerpcHeaderLen:fragLength]
		switch pktType {
		case 0: // Request
			if len(pduBody) >= 8 {
				// allocHint := byteOrder.Uint32(pduBody[0:4])
				// contextID := byteOrder.Uint16(pduBody[4:6])
				opNum := byteOrder.Uint16(pduBody[6:8])
				rec.OpNum = int32(opNum)
			}
		case 11: // Bind
			d.parseBindContextList(pduBody, rec, byteOrder)
		}

		results = append(results, rec)
		offset += int(fragLength)
	}

	return results
}

// parseBindContextList extracts interface UUIDs from Bind packets.
func (d *dcerpcReader) parseBindContextList(body []byte, rec *types.DCERPC, byteOrder binary.ByteOrder) {
	if len(body) < 8 {
		return
	}

	// Bind body: max_xmit_frag(2) + max_recv_frag(2) + assoc_group(4) + num_ctx_items(1) + ...
	// Skip to context list
	// maxXmitFrag := byteOrder.Uint16(body[0:2])
	// maxRecvFrag := byteOrder.Uint16(body[2:4])
	// assocGroup := byteOrder.Uint32(body[4:8])

	if len(body) < 12 {
		return
	}

	numCtxItems := body[8]
	// 3 bytes padding after num_ctx_items
	ctxOffset := 12

	if numCtxItems > 0 && ctxOffset+44 <= len(body) {
		// Each context item: context_id(2) + num_trans_items(1) + reserved(1) + abstract_syntax(20) + transfer_syntax(20*n)
		// Abstract syntax: uuid(16) + version(4)
		if ctxOffset+4+16 <= len(body) {
			// Skip context_id(2) + num_trans_items(1) + reserved(1)
			uuidOffset := ctxOffset + 4
			uuid := formatUUID(body[uuidOffset:uuidOffset+16], byteOrder)
			rec.InterfaceUUID = uuid

			if name, ok := wellKnownInterfaces[uuid]; ok {
				rec.InterfaceName = name
			}
		}
	}
}

// formatUUID converts raw UUID bytes to string in standard format.
// DCE/RPC UUIDs have mixed endianness: first 3 components are byte-order dependent,
// last 2 are big-endian.
func formatUUID(data []byte, byteOrder binary.ByteOrder) string {
	if len(data) < 16 {
		return ""
	}

	timeLow := byteOrder.Uint32(data[0:4])
	timeMid := byteOrder.Uint16(data[4:6])
	timeHiAndVersion := byteOrder.Uint16(data[6:8])

	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		timeLow, timeMid, timeHiAndVersion,
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}
