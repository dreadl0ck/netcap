package ldap

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"strings"
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

type reader struct {
	conversation                                     *core.ConversationInfo
	searches                                         map[int32]string
	saslRequested, saslActive, ntlmKnown, ntlmSealed bool
}

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
		seen          bool
		initialLoss   bool
		qualification string
		plain         []byte
		plainAt       int64
		bytes         []byte
		at            int64
		stopped       bool
	}
	var sides [2]side
	for _, f := range r.conversation.Data {
		index := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			index = 1
		}
		s := &sides[index]
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 {
			r.searches = nil
			if d.SkippedBytes == -1 && !s.seen && len(s.bytes) == 0 {
				s.initialLoss = true
			} else {
				s.bytes = nil
				s.stopped = true
			}
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
		for len(s.bytes) > 0 || len(s.plain) > 0 {
			wrapped := len(s.plain) > 0 || r.saslActive && len(s.bytes) > 0 && s.bytes[0] != 0x30
			consumed := false
			plainLength := frameLength(s.plain)
			if r.saslActive && len(s.bytes) > 0 && s.bytes[0] != 0x30 && (plainLength == 0 || plainLength > len(s.plain)) {
				if len(s.bytes) < 4 {
					break
				}
				length := int(binary.BigEndian.Uint32(s.bytes))
				if length < 1 || length > 1<<20 {
					s.stopped = true
					s.bytes = nil
					break
				}
				if len(s.bytes) < 4+length {
					break
				}
				plain, status := unwrapSASL(s.bytes[4:4+length], r.ntlmKnown, r.ntlmSealed)
				s.bytes = s.bytes[4+length:]
				if plain == nil {
					s.plain = nil
					continue
				}
				if len(s.plain) == 0 {
					s.plainAt = s.at
				}
				if len(s.plain)+len(plain) > 1<<20 {
					s.stopped = true
					s.bytes = nil
					s.plain = nil
					break
				}
				s.plain = append(s.plain, plain...)
				consumed = true
				s.qualification = status
			}
			input, at := s.bytes, s.at
			if wrapped {
				input, at = s.plain, s.plainAt
			}
			n := frameLength(input)
			if n == 0 {
				if consumed && len(s.bytes) > 0 {
					continue
				}
				break
			}
			if n < 0 {
				s.stopped = true
				s.bytes = nil
				break
			}
			if n > len(input) {
				if consumed && len(s.bytes) > 0 {
					continue
				}
				break
			}
			record, ok := parse(input[:n])
			if !ok {
				s.stopped = true
				s.bytes = nil
				break
			}
			record.Timestamp = at
			if record.AuthMechanism == "GSS-SPNEGO" || record.AuthMechanism == "GSSAPI" {
				r.saslRequested = true
			}
			if record.SASLNTLMFlags != 0 {
				r.ntlmKnown = true
				r.ntlmSealed = record.SASLNTLMFlags&0x20 != 0
			}
			if record.Operation == "BindResponse" && record.ResultCode == 0 && r.saslRequested {
				r.saslActive = true
			}
			s.seen = true
			if s.initialLoss {
				record.ReassemblyStatus = "unknown-initial-stream-loss"
			}
			if wrapped && s.qualification != "" {
				if record.ReassemblyStatus != "" {
					record.ReassemblyStatus += ","
				}
				record.ReassemblyStatus += s.qualification
			}
			if record.Operation == "SearchRequest" && record.SearchAccount != "" {
				if r.searches == nil {
					r.searches = map[int32]string{}
				}
				if len(r.searches) < 1024 {
					r.searches[record.MessageID] = record.SearchAccount
				}
			}
			if record.Operation == "SearchResultEntry" {
				record.SearchAccount = r.searches[record.MessageID]
			}
			if record.Operation == "SearchResultDone" {
				delete(r.searches, record.MessageID)
			}
			record.Flow = r.conversation.Ident
			record.CommunityID = r.conversation.CommunityID
			record.SrcIP, record.DstIP, record.SrcPort, record.DstPort = r.conversation.Endpoints(f)
			emit(record)
			if wrapped {
				s.plain = s.plain[n:]
				s.plainAt = core.FragmentTime(f)
			} else {
				s.bytes = s.bytes[n:]
			}
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
		if count == 0 || count > 4 {
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
		value, rest, ok := berValue(b)
		v = value
		if !ok || len(result) >= 4096 {
			return nil, false
		}
		result = append(result, v)
		b = rest
	}
	return result, true
}

func parse(b []byte) (*types.LDAP, bool) {
	outer, rest, valid := berValue(b)
	if !valid || len(rest) != 0 || outer.Class != 0 || outer.Tag != 16 {
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
		if fields[2].Class == 2 && fields[2].Tag == 3 {
			auth, ok := values(fields[2].Bytes)
			if ok && len(auth) > 0 {
				record.AuthMechanism = text(auth[0])
				if len(auth) > 1 {
					record.SASLNTLMFlags = ntlmFlags(auth[1].Bytes)
				}
			}
		}
	case 3, 4:
		if len(fields) < 2 {
			return nil, false
		}
		record.DN = text(fields[0])
		if f[1].Tag == 3 && len(fields) > 6 {
			record.SearchAccount = filterAccount(fields[6], 0)
		}
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
		if len(fields) < 3 || fields[0].Tag != 10 || fields[0].Class != 0 || len(fields[0].Bytes) == 0 || len(fields[0].Bytes) > 4 || fields[1].Tag != 4 || fields[2].Tag != 4 {
			return nil, false
		}
		if len(fields) > 0 && fields[0].Tag == 10 && len(fields[0].Bytes) > 0 && len(fields[0].Bytes) <= 4 {
			var code [4]byte
			copy(code[4-len(fields[0].Bytes):], fields[0].Bytes)
			record.ResultCode = int32(binary.BigEndian.Uint32(code[:]))
		}
		if f[1].Tag == 1 {
			for _, v := range fields {
				if v.Class == 2 && v.Tag == 7 {
					record.SASLNTLMFlags = ntlmFlags(v.Bytes)
				}
			}
		}
	}
	return record, true
}

func ntlmFlags(b []byte) uint32 {
	index := bytes.Index(b, []byte("NTLMSSP\x00"))
	if index < 0 || len(b)-index < 12 {
		return 0
	}
	b = b[index:]
	var offset int
	switch binary.LittleEndian.Uint32(b[8:12]) {
	case 1:
		offset = 12
	case 2:
		offset = 20
	case 3:
		offset = 60
	default:
		return 0
	}
	if len(b) < offset+4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b[offset : offset+4])
}

func unwrapSASL(token []byte, ntlmKnown, ntlmSealed bool) ([]byte, string) {
	if len(token) >= 16 && token[0] == 5 && token[1] == 4 && token[3] == 255 && token[2]&0xf8 == 0 {
		if token[2]&2 != 0 {
			return nil, "sasl-sealed"
		}
		ec, rotation := int(binary.BigEndian.Uint16(token[4:6])), int(binary.BigEndian.Uint16(token[6:8]))
		body := append([]byte(nil), token[16:]...)
		if len(body) == 0 || ec > len(body) {
			return nil, "invalid-sasl"
		}
		rotation %= len(body)
		body = append(body[rotation:], body[:rotation]...)
		return body[:len(body)-ec], "sasl-integrity-not-verified"
	}
	if ntlmKnown && !ntlmSealed && len(token) > 16 && binary.LittleEndian.Uint32(token[:4]) == 1 {
		return token[16:], "sasl-integrity-not-verified"
	}
	return nil, "sasl-sealed-or-unknown"
}

// LDAP is BER, not DER: AD commonly uses padded long-form lengths.
func berValue(b []byte) (asn1.RawValue, []byte, bool) {
	var v asn1.RawValue
	if len(b) < 2 || b[0]&31 == 31 {
		return v, nil, false
	}
	header, n := 2, int(b[1])
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 4 || len(b) < 2+count {
			return v, nil, false
		}
		n = 0
		for _, c := range b[2 : 2+count] {
			n = n<<8 | int(c)
		}
		header += count
	}
	if n > 1<<20 || n < 0 || n > len(b)-header {
		return v, nil, false
	}
	v = asn1.RawValue{Class: int(b[0] >> 6), Tag: int(b[0] & 31), IsCompound: b[0]&32 != 0, Bytes: b[header : header+n], FullBytes: b[:header+n]}
	return v, b[header+n:], true
}

func filterAccount(v asn1.RawValue, depth int) string {
	if depth > 16 || v.Class != 2 {
		return ""
	}
	if v.Tag == 3 {
		pair, ok := values(v.Bytes)
		if ok && len(pair) == 2 && pair[0].Tag == 4 && pair[1].Tag == 4 && strings.EqualFold(string(pair[0].Bytes), "sAMAccountName") && len(pair[1].Bytes) <= 256 {
			return string(pair[1].Bytes)
		}
		return ""
	}
	if v.Tag == 0 {
		children, ok := values(v.Bytes)
		if !ok {
			return ""
		}
		name := ""
		for _, c := range children {
			if n := filterAccount(c, depth+1); n != "" {
				if name != "" && !strings.EqualFold(name, n) {
					return ""
				}
				name = n
			}
		}
		return name
	}
	return ""
}
