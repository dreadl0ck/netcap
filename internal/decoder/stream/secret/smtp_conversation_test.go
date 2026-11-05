package secret

import (
	"encoding/base64"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"strings"
	"testing"
	"time"
)

func TestSMTPAuthExchangesSurvivePacketSplits(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, mechanism := range []string{"LOGIN", "PLAIN"} {
		wire := "AUTH PLAIN " + b64("\x00analyst\x00test-password") + "\r\n"
		if mechanism == "LOGIN" {
			wire = "AUTH LOGIN\r\n" + b64("analyst") + "\r\n" + b64("test-password") + "\r\n"
		}
		for split := 1; split < len(wire); split++ {
			c := &core.ConversationInfo{Ident: "flow", CommunityID: "id", Data: core.DataFragments{
				&core.StreamData{RawData: []byte(wire[:split]), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}},
				&core.StreamData{RawData: []byte(wire[split:]), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(2, 0)}},
				&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("235 authenticated\r\n")},
				&core.StreamData{RawData: []byte(wire)},
			}}
			var records []*types.Secret
			parseSMTPAuth(c, func(r *types.Secret) { records = append(records, r) })
			if len(records) != 2 || records[0].User != "analyst" || records[0].Password != "test-password" || records[0].Timestamp != time.Unix(1, 0).UnixNano() || !strings.HasSuffix(records[0].Notes, "success") || !strings.HasSuffix(records[1].Notes, "unknown") {
				t.Fatal(mechanism, split, records)
			}
		}
	}
}

func TestSMTPAuthStopsAtUpgradeAndIgnoresMailBody(t *testing.T) {
	fake := "AUTH PLAIN AGFuYWx5c3QAcGFzcw==\r\n"
	c := &core.ConversationInfo{Data: core.DataFragments{
		&core.StreamData{RawData: []byte("DATA\r\n")}, &core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("354 send mail\r\n")},
		&core.StreamData{RawData: []byte(fake + ".\r\nSTARTTLS\r\n")}, &core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("220 go encrypted\r\n")}, &core.StreamData{RawData: []byte(fake)},
	}}
	n := 0
	parseSMTPAuth(c, func(*types.Secret) { n++ })
	if n != 0 {
		t.Fatal("body/ciphertext harvested", n)
	}
}
