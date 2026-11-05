package dcerpc

import (
	"encoding/binary"
	"fmt"
	"github.com/dreadl0ck/netcap/types"
	"strings"
	"unicode/utf16"
)

type ndrCursor struct {
	b      []byte
	pos, p int
	order  binary.ByteOrder
	bad    bool
}

func (n *ndrCursor) align(a int) {
	n.pos = (n.pos + a - 1) &^ (a - 1)
	if n.pos > len(n.b) {
		n.bad = true
	}
}
func (n *ndrCursor) take(size int) []byte {
	if size < 0 || n.pos > len(n.b)-size {
		n.bad = true
		return make([]byte, max(0, size))
	}
	b := n.b[n.pos : n.pos+size]
	n.pos += size
	return b
}
func (n *ndrCursor) u16() uint16 { n.align(2); return n.order.Uint16(n.take(2)) }
func (n *ndrCursor) u32() uint32 { n.align(4); return n.order.Uint32(n.take(4)) }
func (n *ndrCursor) ptr() uint64 {
	n.align(n.p)
	if n.p == 8 {
		return n.order.Uint64(n.take(8))
	}
	return uint64(n.u32())
}

type ndrString struct {
	length, maximum uint16
	ptr             uint64
}

func (n *ndrCursor) stringHeader() ndrString {
	n.align(n.p)
	return ndrString{n.u16(), n.u16(), n.ptr()}
}
func (n *ndrCursor) stringData(s ndrString) string {
	if s.length > s.maximum || s.length%2 != 0 || s.maximum > 32768 {
		n.bad = true
		return ""
	}
	if s.ptr == 0 {
		if s.length != 0 {
			n.bad = true
		}
		return ""
	}
	maxCount, offset, count := n.ptr(), n.ptr(), n.ptr()
	if maxCount > 16384 || offset > maxCount || count > maxCount-offset || count*2 != uint64(s.length) {
		n.bad = true
		return ""
	}
	u := make([]uint16, int(count))
	for i := range u {
		u[i] = n.u16()
	}
	return string(utf16.Decode(u))
}
func (n *ndrCursor) sid() string {
	count := n.ptr()
	if count > 15 {
		n.bad = true
		return ""
	}
	b := n.take(8)
	if b[0] != 1 || uint64(b[1]) != count {
		n.bad = true
		return ""
	}
	var authority uint64
	for _, v := range b[2:] {
		authority = authority<<8 | uint64(v)
	}
	sid := fmt.Sprintf("S-1-%d", authority)
	for range int(count) {
		sid += fmt.Sprintf("-%d", n.u32())
	}
	return sid
}
func newNDR(b []byte, is64 bool, order binary.ByteOrder) *ndrCursor {
	p := 4
	if is64 {
		p = 8
	}
	return &ndrCursor{b: b, p: p, order: order}
}

// MS-LSAT 2.2.7, 2.2.18 and 2.2.20: defer pointed-to data after each array.
func lsaInputs(b []byte, op uint16, is64 bool, order binary.ByteOrder) ([]*types.WindowsIdentity, string) {
	n := newNDR(b, is64, order)
	n.take(20)
	if op == 15 {
		n.align(n.p)
	}
	count := n.u32()
	if count == 0 || count > 128 {
		return nil, "array_limit"
	}
	result := make([]*types.WindowsIdentity, int(count))
	for i := range result {
		result[i] = &types.WindowsIdentity{}
	}
	if op == 14 {
		if n.ptr() != uint64(count) {
			return nil, "invalid_ndr_array"
		}
		descs := make([]ndrString, int(count))
		for i := range descs {
			descs[i] = n.stringHeader()
		}
		for i, desc := range descs {
			name := n.stringData(desc)
			domain, account, ok := strings.Cut(name, "\\")
			if !ok {
				account, domain = name, ""
			}
			result[i].AccountName, result[i].Domain = account, domain
		}
	} else {
		if n.ptr() == 0 || n.ptr() != uint64(count) {
			return nil, "invalid_ndr_array"
		}
		pointers := make([]uint64, int(count))
		for i := range pointers {
			pointers[i] = n.ptr()
		}
		for i, p := range pointers {
			if p == 0 {
				n.bad = true
				break
			}
			result[i].SID = n.sid()
		}
	}
	if n.bad {
		return nil, "invalid_ndr_request"
	}
	return result, "decoded_ndr_request"
}

func lsaResults(b []byte, op uint16, is64 bool, order binary.ByteOrder, inputs []*types.WindowsIdentity) ([]*types.WindowsIdentity, string) {
	if len(b) < 8 {
		return nil, "truncated"
	}
	status := order.Uint32(b[len(b)-4:])
	if status != 0 && status != 0x107 {
		return nil, "rpc_error"
	}
	n := newNDR(b, is64, order)
	var domainNames, domainSIDs []string
	if n.ptr() != 0 {
		n.align(n.p)
		count := n.u32()
		pointer := n.ptr()
		n.u32()
		n.align(n.p)
		if count > 128 || count > 0 && pointer == 0 {
			return nil, "invalid_domain_array"
		}
		if pointer != 0 {
			if n.ptr() != uint64(count) {
				return nil, "invalid_domain_array"
			}
			descs := make([]ndrString, int(count))
			pointers := make([]uint64, int(count))
			for i := range descs {
				descs[i] = n.stringHeader()
				pointers[i] = n.ptr()
				n.align(n.p)
			}
			for i, desc := range descs {
				domainNames = append(domainNames, n.stringData(desc))
				sid := ""
				if pointers[i] != 0 {
					sid = n.sid()
				}
				domainSIDs = append(domainSIDs, sid)
			}
		}
	}
	n.align(n.p)
	count := n.u32()
	pointer := n.ptr()
	n.align(n.p)
	if count > 128 || count > 0 && pointer == 0 {
		return nil, "invalid_translation_array"
	}
	uses := make([]uint16, int(count))
	indices := make([]int32, int(count))
	rids := make([]uint32, int(count))
	names := make([]ndrString, int(count))
	if pointer != 0 {
		if n.ptr() != uint64(count) {
			return nil, "invalid_translation_array"
		}
		for i := range uses {
			n.align(n.p)
			uses[i] = n.u16()
			if op == 14 {
				rids[i] = n.u32()
			} else {
				names[i] = n.stringHeader()
			}
			indices[i] = int32(n.u32())
			n.align(n.p)
		}
	}
	var result []*types.WindowsIdentity
	for i, use := range uses {
		name := ""
		if op == 15 {
			name = n.stringData(names[i])
		}
		index := indices[i]
		if index < -1 || index >= int32(len(domainNames)) {
			n.bad = true
			continue
		}
		if use == 0 || use == 8 {
			continue
		}
		identity := &types.WindowsIdentity{}
		if len(inputs) == int(count) {
			identity.AccountName, identity.Domain, identity.SID = inputs[i].AccountName, inputs[i].Domain, inputs[i].SID
		}
		if index >= 0 {
			identity.Domain = domainNames[index]
			if op == 14 && domainSIDs[index] != "" {
				identity.SID = domainSIDs[index]
				if use != 3 {
					identity.SID += fmt.Sprintf("-%d", rids[i])
				}
			}
		}
		if op == 15 {
			identity.AccountName = name
		}
		result = append(result, identity)
	}
	mapped := n.u32()
	returned := n.u32()
	if n.bad || n.pos != len(b) || mapped > count || returned != status {
		return nil, "invalid_ndr_response"
	}
	return result, "decoded_ndr_lookup"
}
