package dcerpc

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/types"
)

func (d *dcerpcReader) decodeIdentityStub(rec *types.DCERPC, pdu []byte, order binary.ByteOrder, level uint16) {
	isQuery := rec.InterfaceName == "SAMR" && (rec.OpNum == 36 || rec.OpNum == 47)
	isLookup := rec.InterfaceName == "LSARPC" && (rec.OpNum == 14 || rec.OpNum == 15)
	if !isQuery && !isLookup {
		return
	}
	if rec.PacketType != ptypeRequest && rec.PacketType != ptypeResponse {
		return
	}
	is64 := d.ndr64[uint16(rec.ContextID)]
	if !d.ndr32[uint16(rec.ContextID)] && !is64 || isLookup && is64 {
		rec.IdentityStatus = "unsupported_or_unconfirmed_transfer_syntax"
		return
	}
	end := len(pdu)
	auth := int(order.Uint16(pdu[10:12]))
	if auth > 0 {
		trailer := end - auth - 8
		if trailer < 24 || pdu[trailer+1] >= 6 {
			rec.IdentityStatus = "encrypted_or_invalid_auth"
			return
		}
		end = trailer - int(pdu[trailer+2])
	}
	if end < 24 {
		rec.IdentityStatus = "truncated"
		return
	}
	if d.stubFragments == nil {
		d.stubFragments = make(map[uint64][]byte)
	}
	key := uint64(uint32(rec.PacketType))<<32 | uint64(uint32(rec.CallID))
	if pdu[3]&1 != 0 {
		if len(d.stubFragments) >= maxPendingCalls {
			rec.IdentityStatus = "assembly_limit"
			return
		}
		d.stubFragments[key] = nil
	}
	bytes, ok := d.stubFragments[key]
	if !ok {
		rec.IdentityStatus = "missing_first_fragment"
		return
	}
	if len(bytes)+end-24 > 1<<20 {
		delete(d.stubFragments, key)
		rec.IdentityStatus = "assembly_limit"
		return
	}
	bytes = append(bytes, pdu[24:end]...)
	d.stubFragments[key] = bytes
	if pdu[3]&2 == 0 {
		rec.IdentityStatus = "pending_fragments"
		return
	}
	delete(d.stubFragments, key)
	if rec.PacketType == ptypeRequest {
		if isLookup {
			rec.Identities, rec.IdentityStatus = lsaLookupInputs(bytes, uint16(rec.OpNum), order)
			return
		}
		if len(bytes) >= 22 {
			calls := d.calls[uint32(rec.CallID)]
			if len(calls) > 0 {
				calls[len(calls)-1].infoClass = order.Uint16(bytes[20:22])
			}
		}
		return
	}
	if isLookup {
		rec.IdentityStatus = "lookup_response_not_decoded"
		return
	}
	ident, status := samrUserIdentity(bytes, level, order)
	if is64 {
		ident, status = samrUserIdentity64(bytes, level, order)
	}
	rec.IdentityStatus = status
	if ident != nil {
		rec.Identities = []*types.WindowsIdentity{ident}
	}
}

// NDR64 widens pointers and conformant-array counts, with 8-byte alignment.
func samrUserIdentity64(b []byte, level uint16, order binary.ByteOrder) (*types.WindowsIdentity, string) {
	if len(b) < 20 {
		return nil, "truncated"
	}
	if order.Uint32(b[len(b)-4:]) != 0 {
		return nil, "rpc_error"
	}
	if order.Uint64(b) == 0 {
		return nil, "null_result"
	}
	if level == 0 || order.Uint16(b[8:10]) != level {
		return nil, "unknown_or_mismatched_information_class"
	}
	var fixed, descriptor, count int
	switch level {
	case 1:
		fixed, count = 72, 2
	case 6:
		fixed, count = 32, 2
	case 7, 8:
		fixed, count = 16, 1
	case 21:
		fixed, descriptor, count = 320, 48, 2
	default:
		return nil, "unsupported_information_class"
	}
	const base = 16
	if len(b) < base+fixed+4 {
		return nil, "truncated"
	}
	pos := base + fixed
	names := make([]string, count)
	for i := range count {
		desc := b[base+descriptor+i*16:]
		length, maximum, ptr := int(order.Uint16(desc)), int(order.Uint16(desc[2:])), order.Uint64(desc[8:])
		if length > maximum || length%2 != 0 {
			return nil, "invalid_ndr_string"
		}
		if ptr == 0 {
			if length != 0 {
				return nil, "invalid_ndr_string"
			}
			continue
		}
		pos = (pos + 7) &^ 7
		if pos+24 > len(b)-4 {
			return nil, "truncated"
		}
		maxCount, offset, actual := order.Uint64(b[pos:]), order.Uint64(b[pos+8:]), order.Uint64(b[pos+16:])
		pos += 24
		if maxCount > 32768 || offset > maxCount || actual > maxCount-offset || actual*2 != uint64(length) || actual*2 > uint64(len(b)-4-pos) {
			return nil, "invalid_ndr_string"
		}
		units := make([]uint16, int(actual))
		for j := range units {
			units[j] = order.Uint16(b[pos+j*2:])
		}
		pos += int(actual) * 2
		names[i] = string(utf16.Decode(units))
	}
	ident := &types.WindowsIdentity{}
	if level == 8 {
		ident.FullName = names[0]
	} else {
		ident.AccountName = names[0]
		if len(names) > 1 {
			ident.FullName = names[1]
		}
	}
	if level == 21 {
		present := order.Uint32(b[base+284:])
		if present&1 == 0 {
			ident.AccountName = ""
		}
		if present&2 == 0 {
			ident.FullName = ""
		}
	}
	return ident, "decoded_ndr64"
}

// MS-LSAT lookup request arrays: expose only explicitly counted input names/SIDs.
func lsaLookupInputs(b []byte, op uint16, order binary.ByteOrder) ([]*types.WindowsIdentity, string) {
	if len(b) < 28 {
		return nil, "truncated"
	}
	count := int(order.Uint32(b[20:]))
	if count < 1 || count > 128 {
		return nil, "array_limit"
	}
	var result []*types.WindowsIdentity
	if op == 14 {
		if int(order.Uint32(b[24:])) != count || 28+count*8 > len(b) {
			return nil, "invalid_ndr_array"
		}
		pos := 28 + count*8
		for i := 0; i < count; i++ {
			desc := b[28+i*8:]
			length := int(order.Uint16(desc))
			maximum := int(order.Uint16(desc[2:]))
			if length%2 != 0 || length > maximum || order.Uint32(desc[4:]) == 0 {
				return nil, "invalid_ndr_string"
			}
			pos = (pos + 3) &^ 3
			if pos+12 > len(b) {
				return nil, "truncated"
			}
			max, off, n := order.Uint32(b[pos:]), order.Uint32(b[pos+4:]), order.Uint32(b[pos+8:])
			pos += 12
			if max > 32768 || off > max || n > max-off || n*2 != uint32(length) || int(n)*2 > len(b)-pos {
				return nil, "invalid_ndr_string"
			}
			u := make([]uint16, int(n))
			for j := range u {
				u[j] = order.Uint16(b[pos+j*2:])
			}
			pos += int(n) * 2
			name := string(utf16.Decode(u))
			domain, account, ok := strings.Cut(name, "\\")
			if !ok {
				account, domain = name, ""
			}
			result = append(result, &types.WindowsIdentity{AccountName: account, Domain: domain})
		}
	} else {
		if len(b) < 32 || order.Uint32(b[24:]) == 0 || int(order.Uint32(b[28:])) != count || 32+count*4 > len(b) {
			return nil, "invalid_ndr_array"
		}
		pos := 32 + count*4
		for i := 0; i < count; i++ {
			if order.Uint32(b[32+i*4:]) == 0 {
				return nil, "null_sid"
			}
			pos = (pos + 3) &^ 3
			if pos+12 > len(b) {
				return nil, "truncated"
			}
			n := int(order.Uint32(b[pos:]))
			pos += 4
			if b[pos] != 1 || n > 15 || int(b[pos+1]) != n || 8+n*4 > len(b)-pos {
				return nil, "invalid_sid"
			}
			var authority uint64
			for _, v := range b[pos+2 : pos+8] {
				authority = authority<<8 | uint64(v)
			}
			sid := fmt.Sprintf("S-1-%d", authority)
			for j := 0; j < n; j++ {
				sid += fmt.Sprintf("-%d", order.Uint32(b[pos+8+j*4:]))
			}
			pos += 8 + n*4
			result = append(result, &types.WindowsIdentity{SID: sid})
		}
	}
	return result, "decoded_ndr32_request"
}

// MS-SAMR SAMPR_USER_INFO_BUFFER, NDR32 discriminated query-result union.
func samrUserIdentity(b []byte, level uint16, order binary.ByteOrder) (*types.WindowsIdentity, string) {
	if len(b) < 12 {
		return nil, "truncated"
	}
	if order.Uint32(b[len(b)-4:]) != 0 {
		return nil, "rpc_error"
	}
	if order.Uint32(b[:4]) == 0 {
		return nil, "null_result"
	}
	if level == 0 || order.Uint16(b[4:6]) != level {
		return nil, "unknown_or_mismatched_information_class"
	}
	var fixed, descriptor, count int
	switch level {
	case 1:
		fixed, descriptor, count = 36, 0, 2
	case 6:
		fixed, descriptor, count = 16, 0, 2
	case 7, 8:
		fixed, descriptor, count = 8, 0, 1
	case 21:
		fixed, descriptor, count = 196, 48, 2
	default:
		return nil, "unsupported_information_class"
	}
	base := 8
	if len(b) < base+fixed+4 {
		return nil, "truncated"
	}
	pos := base + fixed
	var names []string
	for i := 0; i < count; i++ {
		desc := b[base+descriptor+i*8:]
		length, maxLength, ptr := int(order.Uint16(desc)), int(order.Uint16(desc[2:])), order.Uint32(desc[4:])
		if length > maxLength || length%2 != 0 {
			return nil, "invalid_ndr_string"
		}
		if ptr == 0 {
			if length != 0 {
				return nil, "invalid_ndr_string"
			}
			names = append(names, "")
			continue
		}
		pos = (pos + 3) &^ 3
		if pos+12 > len(b)-4 {
			return nil, "truncated"
		}
		maxCount, offset, actual := order.Uint32(b[pos:]), order.Uint32(b[pos+4:]), order.Uint32(b[pos+8:])
		pos += 12
		if maxCount > 32768 || offset > maxCount || actual > maxCount-offset || actual*2 != uint32(length) || int(actual)*2 > len(b)-4-pos {
			return nil, "invalid_ndr_string"
		}
		units := make([]uint16, int(actual))
		for j := range units {
			units[j] = order.Uint16(b[pos+j*2:])
		}
		pos += int(actual) * 2
		names = append(names, string(utf16.Decode(units)))
	}
	ident := &types.WindowsIdentity{}
	if level == 8 {
		ident.FullName = names[0]
	} else {
		ident.AccountName = names[0]
		if len(names) > 1 {
			ident.FullName = names[1]
		}
	}
	if level == 21 {
		present := order.Uint32(b[base+172:])
		if present&1 == 0 {
			ident.AccountName = ""
		}
		if present&2 == 0 {
			ident.FullName = ""
		}
	}
	return ident, "decoded_ndr32"
}
