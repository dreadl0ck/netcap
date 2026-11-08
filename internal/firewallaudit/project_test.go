package firewallaudit

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestNativeProtobufFixtures(t *testing.T) {
	fixtures := []struct {
		record       proto.Message
		field, value string
	}{
		{&types.SMB{SrcIP: "192.0.2.5", CommandName: "CREATE", ShareName: "ADMIN$"}, "ShareName", "ADMIN$"},
		{&types.TLSClientHello{SNI: "blocked.example", CipherSuites: []int32{4865}}, "CipherSuites[0]", "4865"},
		{&types.SMTP{Commands: []string{"AUTH PLAIN synthetic-secret"}}, "Commands[0]", "AUTH PLAIN synthetic-secret"},
		{&types.DNS{Questions: []*types.DNSQuestion{{Name: "blocked.example", Type: 1}}}, "Questions[0].Name", "blocked.example"},
		{&types.Modbus{FunctionCode: 16, Address: 42, WriteValues: []uint32{65535}}, "WriteValues[0]", "65535"},
		{&types.SSH{HasWeakCipher: true, Ident: "SSH-2.0-synthetic"}, "HasWeakCipher", "true"},
		{&types.HTTP{RequestHeader: map[string]string{"Z-Header": "z", "Authorization": "synthetic-secret"}}, "RequestHeader[0].Value", "synthetic-secret"},
	}
	for _, fixture := range fixtures {
		name := reflect.TypeOf(fixture.record).Elem().Name()
		t.Run(name, func(t *testing.T) {
			wire, err := proto.Marshal(fixture.record)
			if err != nil {
				t.Fatal(err)
			}
			decoded := reflect.New(reflect.TypeOf(fixture.record).Elem()).Interface().(proto.Message)
			if err = proto.Unmarshal(wire, decoded); err != nil {
				t.Fatal(err)
			}
			before := proto.Clone(decoded)
			p, err := Project(decoded, nil)
			if err != nil {
				t.Fatal(err)
			}
			if p.Event.Protocol != "audit" || p.Event.RecordType != name || p.Event.Fields[fixture.field] != fixture.value {
				t.Fatalf("projection: %+v", p)
			}
			expression := fmt.Sprintf("Protocol == 'audit' && RecordType == '%s' && Fields['%s'] == %q", name, fixture.field, fixture.value)
			compiled, err := policy.Compile(policy.Bundle{Version: "1", ID: "fixture", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "native", Action: "deny", Expression: expression}}})
			if err != nil {
				t.Fatal(err)
			}
			d, err := compiled.Evaluate(p.Event)
			if err != nil || d.RuleID != "native" {
				t.Fatalf("predicate: %+v %v", d, err)
			}
			if !proto.Equal(before, decoded) {
				t.Fatal("projection mutated decoder record")
			}
		})
	}
}

func TestRegistryCoversCompiledMessagesAndIsIndependent(t *testing.T) {
	c := Discover()
	if len(c.Records) < 200 || !strings.HasPrefix(c.Version, "netcap-audit/v1:") {
		t.Fatalf("incomplete registry: %d", len(c.Records))
	}
	for typ, s := range recordTypes {
		m := reflect.New(typ.Elem()).Interface().(proto.Message)
		p, err := Project(m, nil)
		if err != nil {
			t.Fatalf("%s: %v", s.RecordType, err)
		}
		for key := range p.Event.Fields {
			if !recordFields[typ][key] {
				t.Fatalf("unadvertised field %s.%s", s.RecordType, key)
			}
		}
	}
	c.Records[0].Fields[0].Path = "corrupt"
	if Discover().Records[0].Fields[0].Path == "corrupt" {
		t.Fatal("registry mutable through discovery")
	}
	t.Logf("registered %d exact protobuf record types; version %s", len(c.Records), c.Version)
}

func TestProjectionBoundsAndSourceAttribution(t *testing.T) {
	if _, err := Project(nil, nil); err == nil {
		t.Fatal("nil accepted")
	}
	var typedNil *types.SMB
	if _, err := Project(typedNil, nil); err == nil {
		t.Fatal("typed nil accepted")
	}
	m := &types.HTTP{RequestHeader: map[string]string{}}
	for i := 0; i < MaxItems+1; i++ {
		m.RequestHeader[fmt.Sprint(i)] = "secret"
	}
	p, err := Project(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Truncated || p.Event.Fields["RequestHeader.Length"] != "5" {
		t.Fatal("oversized map not bounded")
	}
	if _, ok := p.Event.Fields["RequestHeader[0].Key"]; ok {
		t.Fatal("oversized map scanned")
	}
	large := &types.TLSClientHello{SNI: strings.Repeat("x", MaxValueBytes+1), Random: make([]byte, MaxValueBytes), CipherSuites: []int32{1, 2, 3, 4, 5}}
	p, err = Project(large, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Truncated || len(p.Event.Fields) > MaxFields || p.Event.Fields["CipherSuites.Length"] != "5" {
		t.Fatal("array/field bounds")
	}
	for _, key := range []string{"SNI", "Random", "CipherSuites[4]"} {
		if _, ok := p.Event.Fields[key]; ok {
			t.Fatalf("clipped/extra field %s", key)
		}
	}
	p, _ = Project(&types.DNS{QueryNameEntropy: math.NaN()}, nil)
	if _, ok := p.Event.Fields["QueryNameEntropy"]; ok || !p.Truncated {
		t.Fatal("nonfinite float admitted")
	}
	ssh := &types.SSH{Flow: "192.0.2.5:55000->198.51.100.7:22", Ident: "192.0.2.5"}
	p, _ = Project(ssh, nil)
	if p.Event.ClientIP != "" || p.Event.Network.SrcIP != "" {
		t.Fatal("inferred IP from SSH text")
	}
	p, _ = Project(ssh, &PacketContext{SrcIP: "192.0.2.5"})
	if p.Event.ClientIP != "192.0.2.5" {
		t.Fatal("trusted context lost")
	}
	for _, src := range []string{"remote.example:22", "192.0.2.5:22", "00:11:22:33:44:55", "127.0.0.1", "::ffff:192.0.2.5", "fe80::1%en0"} {
		p, _ = Project(&types.SMB{SrcIP: src}, nil)
		if p.Event.ClientIP != "" {
			t.Fatalf("unsafe source %s", src)
		}
	}
	data, _ := json.Marshal(Discover())
	if !strings.Contains(string(data), `"sensitivity":"secret"`) {
		t.Fatal("no sensitivity discovery")
	}
}
