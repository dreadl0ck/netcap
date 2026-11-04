package kerberosaudit

import (
	"encoding/asn1"
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func der(t *testing.T, class, tag int, body []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func seq(t *testing.T, b ...[]byte) []byte {
	var body []byte
	for _, v := range b {
		body = append(body, v...)
	}
	return der(t, 0, 16, body)
}
func field(t *testing.T, tag int, b []byte) []byte { return der(t, 2, tag, b) }
func principal(t *testing.T, parts ...string) []byte {
	var values [][]byte
	for _, v := range parts {
		b, err := asn1.MarshalWithParams(v, "general")
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, b)
	}
	return seq(t, field(t, 0, []byte{2, 1, 1}), field(t, 1, seq(t, values...)))
}
func realm(t *testing.T) []byte {
	b, err := asn1.MarshalWithParams("EXAMPLE.TEST", "general")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPrincipalMessageSchemas(t *testing.T) {
	k := &kerberosReader{}
	ticket := der(t, 1, 1, seq(t, field(t, 1, realm(t)), field(t, 2, principal(t, "krbtgt", "EXAMPLE.TEST"))))
	for _, tag := range []int{10, 11, 12, 13, 14, 30} {
		var fields []byte
		switch tag {
		case 10, 12:
			fields = field(t, 4, seq(t, field(t, 1, principal(t, "bdiaz")), field(t, 2, realm(t)), field(t, 3, principal(t, "krbtgt", "EXAMPLE.TEST"))))
		case 11, 13:
			fields = append(append(field(t, 3, realm(t)), field(t, 4, principal(t, "bdiaz"))...), field(t, 5, ticket)...)
		case 14:
			fields = field(t, 3, ticket)
		case 30:
			fields = append(append(field(t, 7, realm(t)), field(t, 8, principal(t, "bdiaz"))...), field(t, 10, principal(t, "krbtgt", "EXAMPLE.TEST"))...)
		}
		wire := der(t, 1, tag, seq(t, fields))
		r := k.parseSingleMessage(wire)
		if r == nil || r.Realm != "EXAMPLE.TEST" || r.ServerName != "krbtgt/EXAMPLE.TEST" || tag != 14 && r.ClientName != "bdiaz" || tag == 14 && r.ClientName != "" {
			t.Fatalf("tag %d: %v", tag, r)
		}
	}
}

func TestKerberosTCPRecordSplitsAndGaps(t *testing.T) {
	msg := der(t, 1, 10, seq(t, field(t, 4, seq(t, field(t, 1, principal(t, "bdiaz")), field(t, 2, realm(t))))))
	wire := binary.BigEndian.AppendUint32(nil, uint32(len(msg)))
	wire = append(wire, msg...)
	wire = append(wire, wire...)
	for split := 1; split < len(wire); split++ {
		for _, gap := range []int{0, 1} {
			fragments := core.DataFragments{&core.StreamData{RawData: wire[:split]}, &core.StreamData{RawData: wire[split:], SkippedBytes: gap}}
			k := &kerberosReader{conversation: &core.ConversationInfo{Data: fragments, ClientData: fragments}}
			var records []*types.Kerberos
			k.decodeMessages(func(r *types.Kerberos, _ core.DataFragment) { records = append(records, r) })
			want := 2
			if gap != 0 {
				want = 0
				if split >= len(wire)/2 {
					want = 1
				}
			}
			if len(records) != want {
				t.Fatalf("split %d gap %d: %v", split, gap, records)
			}
			for _, r := range records {
				if r.ClientName != "bdiaz" {
					t.Fatal(r)
				}
			}
		}
	}
}
