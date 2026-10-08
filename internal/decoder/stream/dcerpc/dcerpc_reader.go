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

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

type dcerpcReader struct {
	conversation *core.ConversationInfo
	// presentation context id -> abstract syntax UUID, learned from Bind and AlterContext
	contexts map[uint16]string
	// call id -> requests awaiting a response, oldest first
	calls   map[uint32][]call
	pending int
}

type call struct {
	context uint16
	opnum   uint16
	uuid    string
}

// New returns a new DCE/RPC reader.
func (d *dcerpcReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &dcerpcReader{
		conversation: conversation,
	}
}

const (
	dcerpcHeaderLen = 16
	maxContexts     = 64
	// maxPendingCalls bounds requests awaiting a response across all call ids.
	maxPendingCalls = 1024
)

const (
	ptypeRequest      = 0
	ptypeResponse     = 2
	ptypeFault        = 3
	ptypeBind         = 11
	ptypeAlterContext = 14
)

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
	"12345778-1234-abcd-ef00-0123456789ac": "SAMR",
	"12345678-1234-abcd-ef00-0123456789ab": "SPOOLSS",
	"338cd001-2244-31f1-aaaa-900038001003": "WINREG",
	"367abb81-9844-35f1-ad32-98f038001003": "SVCCTL",
	"1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC",
	"86d35949-83c9-4044-b424-db363231fd0c": "ITaskSchedulerService",
	"12345778-1234-abcd-ef00-01234567cffb": "NETLOGON",
	"6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC",
	"3919286a-b10c-11d0-9ba8-00c04fd92ef5": "DSSETUP",
	"e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DRSUAPI",
	"4fc742e0-4a10-11cf-8273-00aa004ae673": "DFSNM",
	"c681d488-d850-11d0-8c52-00c04fd90f7e": "EFSR",
}

// operationNames names opnums used in remote administration and credential
// access hunts. Sources: MS-SCMR, MS-TSCH, MS-DRSR, MS-RRP, MS-SAMR, MS-EFSR,
// MS-LSAT/MS-LSAD. An opnum outside this table yields an empty name.
var operationNames = map[string]map[uint16]string{
	"SVCCTL": {0: "RCloseServiceHandle", 1: "RControlService", 2: "RDeleteService", 11: "RChangeServiceConfigW", 12: "RCreateServiceW",
		15: "ROpenSCManagerW", 16: "ROpenServiceW", 19: "RStartServiceW", 24: "RCreateServiceA", 44: "RCreateServiceWOW64W"},
	"ATSVC":                 {0: "NetrJobAdd", 1: "NetrJobDel", 2: "NetrJobEnum", 3: "NetrJobGetInfo"},
	"ITaskSchedulerService": {1: "SchRpcRegisterTask", 12: "SchRpcRun", 13: "SchRpcDelete"},
	"DRSUAPI":               {0: "IDL_DRSBind", 1: "IDL_DRSUnbind", 3: "IDL_DRSGetNCChanges", 12: "IDL_DRSCrackNames"},
	"WINREG":                {2: "OpenLocalMachine", 6: "BaseRegCreateKey", 8: "BaseRegDeleteKey", 15: "BaseRegOpenKey", 17: "BaseRegQueryValue", 22: "BaseRegSetValue"},
	"SAMR": {5: "SamrLookupDomainInSamServer", 6: "SamrEnumerateDomainsInSamServer", 7: "SamrOpenDomain", 13: "SamrEnumerateUsersInDomain",
		17: "SamrLookupNamesInDomain", 34: "SamrOpenUser", 64: "SamrConnect5"},
	"EFSR":   {0: "EfsRpcOpenFileRaw", 4: "EfsRpcEncryptFileSrv"},
	"LSARPC": {14: "LsarLookupNames", 15: "LsarLookupSids", 44: "LsarOpenPolicy2"},
}

// OperationName returns the procedure name for an interface and opnum, or "".
func OperationName(iface string, opnum uint16) string {
	return operationNames[iface][opnum]
}

// Decode parses DCE/RPC PDUs from the stream.
func (d *dcerpcReader) Decode() {
	if Decoder.Writer == nil {
		dcerpcLog.Error("DCERPC Decoder.Writer is nil")
		return
	}

	d.decode(func(rec *types.DCERPC) {
		if err := Decoder.Writer.Write(rec); err != nil {
			dcerpcLog.Error("failed to write dcerpc record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

// decode preserves delivery order across directions. A response never learns
// an operation from a request or binding that arrives later.
func (d *dcerpcReader) decode(emit func(*types.DCERPC)) {
	d.contexts = map[uint16]string{}
	d.calls = map[uint32][]call{}
	d.pending = 0

	fragments := d.conversation.Data
	if len(fragments) == 0 {
		fragments = append(append(core.DataFragments{}, d.conversation.ClientData...), d.conversation.ServerData...)
	}
	type side struct {
		data []byte
		at   int64
	}
	var sides [2]side
	for _, f := range fragments {
		index := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			index = 1
		}
		b := &sides[index]
		if gap, ok := f.(*core.StreamData); ok && gap.SkippedBytes != 0 {
			b.data = nil
			d.contexts = map[uint16]string{}
			d.calls = map[uint32][]call{}
			d.pending = 0
			continue
		}
		raw := f.Raw()
		for len(raw) > 0 {
			if len(b.data) == 0 {
				b.at = core.FragmentTime(f)
			}
			if len(b.data) < dcerpcHeaderLen {
				n := min(dcerpcHeaderLen-len(b.data), len(raw))
				b.data = append(b.data, raw[:n]...)
				raw = raw[n:]
				if len(b.data) < dcerpcHeaderLen {
					break
				}
			}
			pdu := b.data
			var order binary.ByteOrder = binary.LittleEndian
			if pdu[4]&0x10 == 0 {
				order = binary.BigEndian
			}
			length := int(order.Uint16(pdu[8:10]))
			if pdu[0] != 5 || pdu[1] > 1 || pdu[2] > 19 || length < dcerpcHeaderLen {
				b.data = nil
				break
			}
			n := min(length-len(b.data), len(raw))
			b.data = append(b.data, raw[:n]...)
			raw = raw[n:]
			if len(b.data) < length {
				break
			}
			rec := d.parsePDU(b.data, order)
			rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort = d.conversation.Endpoints(f)
			rec.Timestamp = b.at
			rec.Flow, rec.CommunityID = d.conversation.Ident, d.conversation.CommunityID
			emit(rec)
			b.data = b.data[:0]
		}
	}
}

func (d *dcerpcReader) parsePDU(pdu []byte, order binary.ByteOrder) *types.DCERPC {
	pktType := int(pdu[2])
	callID := order.Uint32(pdu[12:16])

	pktTypeName := packetTypeNames[pktType]
	if pktTypeName == "" {
		pktTypeName = "Unknown"
	}

	rec := &types.DCERPC{
		Version:        int32(pdu[0]),
		VersionMinor:   int32(pdu[1]),
		PacketType:     int32(pktType),
		PacketTypeName: pktTypeName,
		Flags:          int32(pdu[3]),
		FragLength:     int32(len(pdu)),
		CallID:         int32(callID),
	}

	body := pdu[dcerpcHeaderLen:]
	switch pktType {
	case ptypeRequest:
		// alloc_hint(4) p_cont_id(2) opnum(2)
		if len(body) >= 8 {
			ctx, opnum := order.Uint16(body[4:6]), order.Uint16(body[6:8])
			rec.ContextID, rec.OpNum = int32(ctx), int32(opnum)
			d.attribute(rec, ctx, opnum, true)
			// Only the first fragment of a request starts a call.
			if pdu[3]&0x01 != 0 && d.pending < maxPendingCalls {
				d.calls[callID] = append(d.calls[callID], call{context: ctx, opnum: opnum, uuid: d.contexts[ctx]})
				d.pending++
			}
		}
	case ptypeResponse, ptypeFault:
		// alloc_hint(4) p_cont_id(2) cancel_count(1) reserved(1) [status(4) for Fault]
		if len(body) >= 6 {
			ctx := order.Uint16(body[4:6])
			rec.ContextID = int32(ctx)
			request, known := d.complete(callID, ctx, pdu[3]&0x02 != 0 || pktType == ptypeFault)
			if known {
				rec.OpNum = int32(request.opnum)
				rec.InterfaceUUID = request.uuid
				rec.InterfaceName = wellKnownInterfaces[request.uuid]
				rec.OperationName = OperationName(rec.InterfaceName, request.opnum)
			} else {
				d.attribute(rec, ctx, 0, false)
			}
		}
		if pktType == ptypeFault && len(body) >= 12 {
			rec.FaultStatus = order.Uint32(body[8:12])
		}
	case ptypeBind, ptypeAlterContext:
		d.parseContextList(body, rec, order)
	}

	return rec
}

// attribute sets interface and operation names from a learned context.
func (d *dcerpcReader) attribute(rec *types.DCERPC, ctx, opnum uint16, opnumKnown bool) {
	uuid, ok := d.contexts[ctx]
	if !ok {
		return
	}
	rec.InterfaceUUID = uuid
	rec.InterfaceName = wellKnownInterfaces[uuid]
	if opnumKnown {
		rec.OperationName = OperationName(rec.InterfaceName, opnum)
	}
}

// complete returns the opnum of the oldest request for callID on ctx and
// removes it when this is the last fragment of the reply.
func (d *dcerpcReader) complete(callID uint32, ctx uint16, last bool) (call, bool) {
	pending := d.calls[callID]
	for i, c := range pending {
		if c.context != ctx {
			continue
		}
		if last {
			d.pending--
			pending = append(pending[:i:i], pending[i+1:]...)
			if len(pending) == 0 {
				delete(d.calls, callID)
			} else {
				d.calls[callID] = pending
			}
		}
		return c, true
	}
	return call{}, false
}

// parseContextList records every presentation context of a Bind or
// AlterContext body; the record keeps the first context's interface.
func (d *dcerpcReader) parseContextList(body []byte, rec *types.DCERPC, order binary.ByteOrder) {
	// max_xmit_frag(2) max_recv_frag(2) assoc_group(4) num_ctx_items(1) pad(3)
	if len(body) < 12 {
		return
	}

	n := int(body[8])
	at := 12
	for i := 0; i < n; i++ {
		// context_id(2) num_trans_items(1) reserved(1) abstract_syntax(uuid 16 + version 4) transfer_syntaxes(20 each)
		if at+24 > len(body) {
			return
		}
		ctx := order.Uint16(body[at : at+2])
		transfers := int(body[at+2])
		uuid := formatUUID(body[at+4:at+20], order)
		if i == 0 {
			rec.InterfaceUUID = uuid
			rec.InterfaceName = wellKnownInterfaces[uuid]
		}
		if _, exists := d.contexts[ctx]; exists || len(d.contexts) < maxContexts {
			d.contexts[ctx] = uuid
		}
		at += 24 + 20*transfers
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
