package apipolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestProto2DescriptorRequiredFields(t *testing.T) {
	source := `syntax="proto2"; package legacy; message Request { required int64 id=1; optional string token=2; } service Service { rpc Call(Request) returns (Request); }`
	c := protocompile.Compiler{Resolver: &protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(map[string]string{"legacy.proto": source})}}
	files, err := c.Compile(context.Background(), "legacy.proto")
	if err != nil {
		t.Fatal(err)
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(files[0])}}
	artifact, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bundle{methods: map[string]*grpcMethod{}}
	if err := b.compileGRPC(artifact, map[string]MethodPolicy{"/legacy.Service/Call": {Request: map[string]FieldPolicy{"id": {Required: true, Schema: parsed(t, `{"type":"integer","minimum":1}`)}}}}, nil); err != nil {
		t.Fatal(err)
	}
	if b.ValidateGRPC("/legacy.Service/Call", false, nil) == nil {
		t.Fatal("missing proto2 required field accepted")
	}
	if err := b.ValidateGRPC("/legacy.Service/Call", false, []byte{8, 1}); err != nil {
		t.Fatal("valid proto2 message rejected", err)
	}
}

func TestCompiledDescriptorTypedPolicies(t *testing.T) {
	source := `syntax="proto3"; package test;
	message Child { int64 amount=1; Child next=2; }
	message Request {
	 enum State { UNKNOWN=0; OK=1; }
	 Child child=1; State state=2; oneof choice { string note=3; int32 number=4; }
	 repeated string labels=5; optional bool explicit=6; repeated int64 amounts=7;
	}
	service Service { rpc Exchange(stream Request) returns (stream Request); }`
	c := protocompile.Compiler{Resolver: &protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(map[string]string{"test.proto": source})}}
	files, err := c.Compile(context.Background(), "test.proto")
	if err != nil {
		t.Fatal(err)
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(files[0])}}
	artifact, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	schema := func(s string) any { return parsed(t, s) }
	p := map[string]MethodPolicy{"/test.Service/Exchange": {Request: map[string]FieldPolicy{
		"child.amount": {Required: true, Schema: schema(`{"type":"integer","const":7}`)},
		"state":        {Schema: schema(`{"enum":["OK",99]}`)},
		"note":         {Required: true, Schema: schema(`{"type":"string","const":"safe"}`)},
		"labels":       {Schema: schema(`{"type":"array","minItems":1,"items":{"type":"string","maxLength":8}}`)},
		"explicit":     {Required: true, Schema: schema(`{"const":false}`)},
	}, Response: map[string]FieldPolicy{"child.amount": {Required: true, Schema: schema(`{"type":"integer","maximum":10}`)}}}}
	b := &Bundle{methods: map[string]*grpcMethod{}}
	if err := b.compileGRPC(artifact, p, nil); err != nil {
		t.Fatal(err)
	}
	md := files[0].Messages().ByName("Request")
	makeMessage := func() *dynamicpb.Message {
		m := dynamicpb.NewMessage(md)
		cf := md.Fields().ByName("child")
		child := dynamicpb.NewMessage(cf.Message())
		child.Set(cf.Message().Fields().ByName("amount"), protoreflect.ValueOfInt64(7))
		m.Set(cf, protoreflect.ValueOfMessage(child))
		m.Set(md.Fields().ByName("state"), protoreflect.ValueOfEnum(1))
		m.Set(md.Fields().ByName("note"), protoreflect.ValueOfString("safe"))
		m.Mutable(md.Fields().ByName("labels")).List().Append(protoreflect.ValueOfString("hello"))
		m.Set(md.Fields().ByName("explicit"), protoreflect.ValueOfBool(false))
		return m
	}
	marshal := func(m proto.Message) []byte {
		t.Helper()
		data, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := b.ValidateGRPC("/test.Service/Exchange", false, marshal(makeMessage())); err != nil {
		t.Fatal("valid typed message denied", err)
	}
	for _, mutate := range []func(*dynamicpb.Message){
		func(m *dynamicpb.Message) { m.Clear(md.Fields().ByName("child")) },
		func(m *dynamicpb.Message) {
			m.Get(md.Fields().ByName("child")).Message().Set(md.Fields().ByName("child").Message().Fields().ByName("amount"), protoreflect.ValueOfInt64(8))
		},
		func(m *dynamicpb.Message) { m.Set(md.Fields().ByName("state"), protoreflect.ValueOfEnum(2)) },
		func(m *dynamicpb.Message) { m.Set(md.Fields().ByName("number"), protoreflect.ValueOfInt32(3)) },
		func(m *dynamicpb.Message) { m.Clear(md.Fields().ByName("explicit")) },
		func(m *dynamicpb.Message) { m.Clear(md.Fields().ByName("labels")) },
	} {
		m := makeMessage()
		mutate(m)
		if b.ValidateGRPC("/test.Service/Exchange", false, marshal(m)) == nil {
			t.Fatal("invalid typed field accepted", m)
		}
	}
	m := makeMessage()
	m.Set(md.Fields().ByName("state"), protoreflect.ValueOfEnum(99))
	wire := marshal(m)
	wire = protowire.AppendBytes(protowire.AppendTag(wire, 100, protowire.BytesType), []byte("unknown future field"))
	if err := b.ValidateGRPC("/test.Service/Exchange", false, wire); err != nil {
		t.Fatal("unknown enum/field lost", err)
	}
	if err := b.GRPCMethod("/test.Service/Unknown"); err == nil {
		t.Fatal("unknown RPC silently accepted")
	}
	if err := b.ValidateGRPC("/test.Service/Exchange", false, []byte{10, 255}); err == nil {
		t.Fatal("malformed protobuf accepted")
	}
	for _, field := range []protowire.Number{5, 7, 100} {
		var bomb []byte
		if field == 7 {
			bomb = protowire.AppendBytes(protowire.AppendTag(nil, field, protowire.BytesType), make([]byte, MaxNodes+1))
		} else {
			for i := 0; i <= MaxNodes; i++ {
				bomb = protowire.AppendBytes(protowire.AppendTag(bomb, field, protowire.BytesType), nil)
			}
		}
		n := 0
		if checkWire(bomb, md, 0, &n) == nil {
			t.Fatalf("pre-decode wire budget bypass for field %d", field)
		}
	}
	child := []byte{8, 7}
	for i := 0; i < MaxDepth+1; i++ {
		child = protowire.AppendBytes(protowire.AppendTag([]byte{8, 7}, 2, protowire.BytesType), child)
	}
	deep := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), child)
	if b.ValidateGRPC("/test.Service/Exchange", false, deep) == nil {
		t.Fatal("protobuf depth budget bypass")
	}
	if b.ValidateGRPC("/test.Service/Exchange", false, []byte(strings.Repeat("x", MaxBytes+1))) == nil {
		t.Fatal("protobuf byte budget bypass")
	}
	p["/test.Service/Exchange"] = MethodPolicy{Request: map[string]FieldPolicy{"noSuchField": {Schema: true}}}
	if b.compileGRPC(artifact, p, nil) == nil {
		t.Fatal("typo field silently ignored")
	}
}
