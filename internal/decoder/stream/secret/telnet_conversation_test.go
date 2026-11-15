package secret

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

func TestTelnetDirectionalCredentialsWithNULAndNegotiation(t *testing.T) {
	for _, padded := range []bool{false, true} {
		var data core.DataFragments
		add := func(server bool, wire []byte) {
			dir := reassembly.TCPDirClientToServer
			if server {
				dir = reassembly.TCPDirServerToClient
			}
			for _, b := range wire {
				data = append(data, &core.StreamData{Dir: dir, RawData: []byte{b}})
			}
		}
		add(true, []byte{255, 251, 1, 255, 250, 24, 1, 255, 240})
		add(true, []byte("login:"))
		for _, b := range []byte("aabb") {
			add(false, []byte{b})
			if padded {
				add(true, []byte{b, 0})
			}
		}
		add(false, []byte{'\r', 0, '\n'})
		add(true, []byte("\r\nPassword:"))
		add(false, []byte("synthetic-pass\r\n"))
		var records []*types.Secret
		parseTelnetAuth(&core.ConversationInfo{Data: data}, func(r *types.Secret) { records = append(records, r) })
		if len(records) != 1 || records[0].User != "aabb" || records[0].Password != "synthetic-pass" {
			t.Fatal(padded, records)
		}
	}
}
