package ldap

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestADPaddedBERLengthIsNotTreatedAsDER(t *testing.T) {
	wire := entry()
	padded := append([]byte{0x30, 0x84, 0, 0, 0, wire[1]}, wire[2:]...)
	if !Decoder.CanDecode(nil, padded) {
		t.Fatal("AD BER length rejected")
	}
	r := &reader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{SkippedBytes: -1}, &core.StreamData{RawData: padded}}}}
	var records []*types.LDAP
	r.decode(func(m *types.LDAP) { records = append(records, m) })
	if len(records) != 1 || records[0].ReassemblyStatus != "unknown-initial-stream-loss" {
		t.Fatal(records)
	}
}
