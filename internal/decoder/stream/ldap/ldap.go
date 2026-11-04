package ldap

import (
	"encoding/asn1"
	"encoding/binary"
	"sync/atomic"
	"unicode/utf8"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

var operations = map[int]string{0: "BindRequest", 1: "BindResponse", 2: "UnbindRequest", 3: "SearchRequest", 4: "SearchResultEntry", 5: "SearchResultDone", 6: "ModifyRequest", 7: "ModifyResponse", 8: "AddRequest", 9: "AddResponse", 10: "DeleteRequest", 11: "DeleteResponse", 12: "ModifyDNRequest", 13: "ModifyDNResponse", 14: "CompareRequest", 15: "CompareResponse", 16: "AbandonRequest", 19: "SearchResultReference", 23: "ExtendedRequest", 24: "ExtendedResponse", 25: "IntermediateResponse"}

var Decoder = &decoder.StreamDecoder{Name: "LDAP", Type: types.Type_NC_LDAP, Description: "LDAP over TCP, including directory identity attributes", Specificity: core.SpecificityStructural, Typ: core.TCP, Factory: &reader{}, CanDecode: func(client, server []byte) bool {
	for _, b := range [][]byte{client, server} {
		n := frameLength(b)
		if n > 0 && n <= len(b) {
			if _, ok := parse(b[:n]); ok {
				return true
			}
		}
	}
	return false
}}

type reader struct{ conversation *core.ConversationInfo }

func (r *reader) New(c *core.ConversationInfo) core.StreamDecoderInterface {
	return &reader{conversation: c}
}
func (r *reader) Decode() {
	if Decoder.Writer == nil {
		return
	}
	r.decode(func(record *types.LDAP) {
		if Decoder.Writer.Write(record) == nil {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

func (r *reader) decode(emit func(*types.LDAP)) {
	type side struct {
		bytes   []byte
		at      int64
		stopped bool
	}
	var sides [2]side
	for _, f := range r.conversation.Data {
		index := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			index = 1
		}
		s := &sides[index]
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 {
			s.bytes = nil
			s.stopped = true
		}
		if s.stopped {
			continue
		}
		if len(s.bytes) == 0 {
			s.at = core.FragmentTime(f)
		}
		if len(s.bytes)+len(f.Raw()) > 2<<20 {
			s.stopped = true
			s.bytes = nil
			continue
		}
		s.bytes = append(s.bytes, f.Raw()...)
		for len(s.bytes) > 0 {
			n := frameLength(s.bytes)
			if n == 0 {
				break
			}
			if n < 0 {
				s.stopped = true
				s.bytes = nil
				break
			}
			if n > len(s.bytes) {
				break
			}
			record, ok := parse(s.bytes[:n])
			if !ok {
				s.stopped = true
				s.bytes = nil
				break
			}
			record.Timestamp = s.at
			record.Flow = r.conversation.Ident
			record.CommunityID = r.conversation.CommunityID
			record.SrcIP, record.DstIP, record.SrcPort, record.DstPort = r.conversation.Endpoints(f)
			emit(record)
			s.bytes = s.bytes[n:]
			s.at = core.FragmentTime(f)
		}
	}
}

// LDAP uses definite BER lengths; indefinite and oversized messages are refused.
func frameLength(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	if b[0] != 0x30 {
		return -1
	}
	if len(b) < 2 {
		return 0
	}
	n, header := int(b[1]), 2
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 3 {
			return -1
		}
		if len(b) < 2+count {
			return 0
		}
		n = 0
		for _, v := range b[2 : 2+count] {
			n = n<<8 | int(v)
		}
		header += count
	}
	if n < 5 || n > 1<<20 {
		return -1
	}
	return header + n
}

func values(b []byte) ([]asn1.RawValue, bool) {
	var result []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil || len(result) >= 4096 {
			return nil, false
		}
		result = append(result, v)
		b = rest
	}
	return result, true
}

func parse(b []byte) (*types.LDAP, bool) {
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(b, &outer); err != nil || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 {
		return nil, false
	}
	f, ok := values(outer.Bytes)
	if !ok || len(f) < 2 || f[0].Tag != 2 || f[0].Class != 0 || len(f[0].Bytes) == 0 || len(f[0].Bytes) > 4 || f[0].Bytes[0]&128 != 0 || f[1].Class != 1 {
		return nil, false
	}
	var id uint32
	for _, v := range f[0].Bytes {
		id = id<<8 | uint32(v)
	}
	op, ok := operations[f[1].Tag]
	if !ok {
		return nil, false
	}
	record := &types.LDAP{MessageID: int32(id), Operation: op}
	if !f[1].IsCompound {
		return record, true
	}
	fields, ok := values(f[1].Bytes)
	if !ok {
		return nil, false
	}
	text := func(v asn1.RawValue) string {
		if v.Class == 0 && v.Tag == 4 && utf8.Valid(v.Bytes) {
			return string(v.Bytes)
		}
		return ""
	}
	switch f[1].Tag {
	case 0:
		if len(fields) < 3 || fields[0].Tag != 2 {
			return nil, false
		}
		record.DN = text(fields[1])
	case 3, 4:
		if len(fields) < 2 {
			return nil, false
		}
		record.DN = text(fields[0])
		if f[1].Tag == 4 {
			attrs, ok := values(fields[1].Bytes)
			if !ok {
				return nil, false
			}
			for _, attr := range attrs {
				pair, ok := values(attr.Bytes)
				if !ok || len(pair) != 2 {
					return nil, false
				}
				name := text(pair[0])
				if name == "" {
					return nil, false
				}
				vv, ok := values(pair[1].Bytes)
				if !ok {
					return nil, false
				}
				a := &types.LDAPAttribute{Name: name}
				for _, v := range vv {
					if v.Tag != 4 || v.Class != 0 {
						return nil, false
					}
					a.Values = append(a.Values, append([]byte(nil), v.Bytes...))
				}
				record.Attributes = append(record.Attributes, a)
			}
		}
	case 1, 5, 7, 9, 11, 13, 15, 24:
		if len(fields) > 0 && fields[0].Tag == 10 && len(fields[0].Bytes) > 0 && len(fields[0].Bytes) <= 4 {
			var code [4]byte
			copy(code[4-len(fields[0].Bytes):], fields[0].Bytes)
			record.ResultCode = int32(binary.BigEndian.Uint32(code[:]))
		}
	}
	return record, true
}
