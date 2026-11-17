package stream

import (
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/protobuf"
)

func TestExplicitProtobufSelectionPreservesSingleFieldMessages(t *testing.T) {
	old := decoderconfig.Instance
	config := decoderconfig.DefaultConfig.Clone()
	decoderconfig.Instance = config
	defer func() { decoderconfig.Instance = old }()
	weak := []byte{0x09, 1, 2, 3, 4, 5, 6, 7, 8}
	in := &SelectionInput{Transport: core.UDP, ServerPort: 60001, Datagrams: []Datagram{{Data: weak, Client: true}}}
	if _, ok := matchScore(protobuf.Decoder, in, false); ok {
		t.Fatal("weak message admitted without intent")
	}
	config.IncludeDecoders = "Protobuf"
	if _, ok := matchScore(protobuf.Decoder, in, false); !ok {
		t.Fatal("explicit single-field Protobuf was rejected")
	}
}

func TestWireFormatAloneDoesNotClaimConversation(t *testing.T) {
	previous := decoderconfig.Instance
	defer func() { decoderconfig.Instance = previous }()
	decoderconfig.Instance = &decoderconfig.Config{}
	data := []byte{0x08, 0x01, 0x12, 0x03, 'a', 'b', 'c'}
	if !protobuf.ValidConfiguredData(data) {
		t.Fatal("control is not valid wire data")
	}
	in := &SelectionInput{Transport: core.TCP, ServerPort: 45678, PortClient: data, ScanClient: data}
	for _, portPass := range []bool{true, false} {
		if _, ok := matchScore(protobuf.Decoder, in, portPass); ok {
			t.Fatal("unconfigured wire data claimed a protocol")
		}
	}
	decoderconfig.Instance.IncludeDecoders = "Protobuf"
	if _, ok := matchScore(protobuf.Decoder, in, false); !ok {
		t.Fatal("explicit wire exploration was lost")
	}
}
