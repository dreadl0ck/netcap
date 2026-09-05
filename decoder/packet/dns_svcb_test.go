package packet

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
)

func TestDNSSVCB(t *testing.T) {
	encoder.SetConfig(&encoder.Config{MinMax: true})
	previous := conf
	conf = &config.Config{}
	t.Cleanup(func() { conf = previous })
	for _, typ := range []layers.DNSType{layers.DNSTypeSVCB, layers.DNSTypeHTTPS} {
		rr := layers.DNSResourceRecord{Name: []byte("example.com"), Type: typ, Class: layers.DNSClassIN,
			SVCB: layers.DNSSVCB{Priority: 1, Target: []byte("svc.example.com"), Params: []layers.DNSSvcParam{
				{Key: 0, Value: []byte{0, 1, 0, 3}}, {Key: 1, Value: []byte{2, 'h', '2', 2, 'h', '3'}},
				{Key: 2}, {Key: 3, Value: []byte{1, 187}}, {Key: 4, Value: []byte{192, 0, 2, 1}},
				{Key: 5, Value: []byte{0, 5, 0xfe, 0x0d, 0, 1, 0}}, {Key: 6, Value: make([]byte, 16)},
				{Key: 7, Value: []byte("/dns-query{?dns}")}, {Key: 65400, Value: []byte{0xff, 0}},
			}}}
		input := &layers.DNS{QR: true, Answers: []layers.DNSResourceRecord{rr}, Authorities: []layers.DNSResourceRecord{rr}, Additionals: []layers.DNSResourceRecord{rr}}
		buf := gopacket.NewSerializeBuffer()
		if err := input.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
			t.Fatal(err)
		}
		var dns layers.DNS
		if err := dns.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		record := dnsDecoder.Handler(&dns, 123).(*types.DNS)
		for _, section := range [][]*types.DNSResourceRecord{record.Answers, record.Authorities, record.Additionals} {
			s := section[0].SVCB
			if s == nil || s.Invalid || s.Priority != 1 || s.Target != "svc.example.com" || len(s.Params) != 9 {
				t.Fatalf("bad SVCB: %v", s)
			}
			if len(s.Params[0].Mandatory) != 2 || string(s.Params[1].ALPN[1]) != "h3" || !s.Params[2].NoDefaultALPN || s.Params[3].Port != 443 || s.Params[4].IPv4Hints[0] != "192.0.2.1" || len(s.Params[5].ECH) != 7 || s.Params[6].IPv6Hints[0] != "::" || s.Params[7].DoHPath != "/dns-query{?dns}" {
				t.Fatalf("missing convenience fields: %v", s)
			}
			if s.Params[8].Decoded || !bytes.Equal(s.Params[8].Value, []byte{0xff, 0}) || len(section[0].Data) == 0 {
				t.Fatal("raw data lost")
			}
		}
		wire, err := proto.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip types.DNS
		if err = proto.Unmarshal(wire, &roundtrip); err != nil || !proto.Equal(record, &roundtrip) {
			t.Fatalf("roundtrip: %v", err)
		}
		if !strings.Contains(strings.Join(record.CSVRecord(), ""), "svc.example.com") || len(record.CSVRecord()) != len(record.CSVHeader()) || len(record.Encode()) != len(record.CSVHeader()) {
			t.Fatal("CSV/encoded export")
		}
		json, err := record.JSON()
		if err != nil || !strings.Contains(json, "65400") {
			t.Fatalf("JSON export: %s %v", json, err)
		}
	}
}

func TestDNSSVCBInvalid(t *testing.T) {
	for _, p := range []layers.DNSSvcParam{
		{Key: 0}, {Key: 0, Value: []byte{0, 0}}, {Key: 0, Value: []byte{0, 3}},
		{Key: 1, Value: []byte{0}}, {Key: 1, Value: []byte{2, 'h'}}, {Key: 2, Value: []byte{1}}, {Key: 2},
		{Key: 3, Value: []byte{1}}, {Key: 4, Value: []byte{1, 2, 3}}, {Key: 6, Value: make([]byte, 15)},
		{Key: 5, Value: []byte{0, 4, 0, 1, 0, 2}}, {Key: 5, Value: []byte{0, 1, 0}},
		{Key: 5, Value: []byte{0, 0}},
		{Key: 7, Value: []byte("/dns-query")}, {Key: 7, Value: []byte("/dns{?dns}{")}, {Key: 65535},
	} {
		s := dnsSVCB(layers.DNSResourceRecord{Type: layers.DNSTypeHTTPS, SVCB: layers.DNSSVCB{Params: []layers.DNSSvcParam{p}}})
		if !s.Invalid || s.Params[0].Decoded || s.Params[0].Error == "" || !bytes.Equal(s.Params[0].Value, p.Value) || len(s.Params[0].ALPN) != 0 {
			t.Fatalf("invalid key %d value %x: %v", p.Key, p.Value, s)
		}
	}
	for _, params := range [][]layers.DNSSvcParam{{{Key: 3, Value: []byte{0, 1}}, {Key: 3, Value: []byte{0, 2}}}, {{Key: 9}, {Key: 8}}} {
		s := dnsSVCB(layers.DNSResourceRecord{Type: layers.DNSTypeSVCB, SVCB: layers.DNSSVCB{Params: params}})
		if !s.Invalid || len(s.Params) != 2 || s.Params[0].Key != uint32(params[0].Key) {
			t.Fatal("order lost")
		}
	}
	if dnsSVCB(layers.DNSResourceRecord{Type: layers.DNSTypeA}) != nil {
		t.Fatal("SVCB on A record")
	}
}
