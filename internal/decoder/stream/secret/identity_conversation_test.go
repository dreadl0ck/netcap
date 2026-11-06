package secret

import (
	"encoding/binary"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"testing"
	"unicode/utf16"
)

func TestNTLMIdentityAcrossSplitsAndReverseDirection(t *testing.T) {
	b := make([]byte, 64)
	copy(b, ntlmsspSignature)
	binary.LittleEndian.PutUint32(b[8:], 3)
	binary.LittleEndian.PutUint32(b[60:], 1)
	u := utf16.Encode([]rune("Analyst"))
	binary.LittleEndian.PutUint16(b[36:], uint16(len(u)*2))
	binary.LittleEndian.PutUint16(b[38:], uint16(len(u)*2))
	binary.LittleEndian.PutUint32(b[40:], 64)
	for _, v := range u {
		b = binary.LittleEndian.AppendUint16(b, v)
	}
	for split := 1; split < len(b); split++ {
		c := &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 389, Data: core.DataFragments{&core.StreamData{RawData: b[:split], Dir: reassembly.TCPDirServerToClient}, &core.StreamData{RawData: b[split:], Dir: reassembly.TCPDirServerToClient}}}
		var identities []*types.Secret
		harvestNTLMIdentity(c, func(r *types.Secret) { identities = append(identities, r) })
		if len(identities) != 1 || identities[0].User != "Analyst" || identities[0].Password != "" || identities[0].Flow != "192.0.2.2:389->192.0.2.1:40000" {
			t.Fatal(split, identities)
		}
		c.Data[1].(*core.StreamData).SkippedBytes = 1
		harvestNTLMIdentity(c, func(*types.Secret) { t.Fatal("identity stitched across gap") })
	}
	binary.LittleEndian.PutUint32(b[40:], 65535)
	if identityToken(b) != nil {
		t.Fatal("invalid security-buffer range accepted")
	}
}
