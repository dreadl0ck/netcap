package secret

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func TestRound2TeamViewerRejectsEmbeddedMagic(t *testing.T) {
	for _, prefix := range []string{"STEAMDISCOVER", "\x00\x00\x00\x20\x6a\x1e", "POST / HTTP/1.1\r\n\r\n"} {
		data := append([]byte(prefix), makeTeamViewerPacket(45)...)
		if s := teamviewerHarvesterFunc(data, "negative", time.Unix(1, 0)); s != nil {
			t.Errorf("%q: arbitrary embedded magic produced %s", prefix, s.Service)
		}
	}
}

func TestRound2TeamViewerCapturedFraming(t *testing.T) {
	// nDPI@d0eeed4f teamviewer.pcap, TCP payloads in frames 4 and 12.
	// They identify TeamViewer, but are not authentication observations.
	for _, tc := range []struct {
		wire    string
		command byte
	}{
		{"17240a200000000000000000004800800001000000148000006fb78c804805532216142004", 10},
		{"113036001800000001000000000000001b000000180000008c0067fc71b09880d95938c589a6c18cc7919eea283d28cd", 54},
	} {
		data, _ := hex.DecodeString(tc.wire)
		p := parseRemoteDesktopPacket(data)
		if p == nil || p.CommandCode != tc.command || p.Size != len(data) {
			t.Fatalf("real TeamViewer frame rejected: %v", p)
		}
		if teamviewerHarvesterFunc(data, "real", time.Unix(1, 0)) != nil {
			t.Fatal("non-auth frame emitted a Secret")
		}
	}
}

func TestRound2TeamViewerConversationFraming(t *testing.T) {
	v2 := make([]byte, 40)
	copy(v2, []byte{0x11, 0x30, 103, 0})
	binary.LittleEndian.PutUint32(v2[4:8], 16)
	binary.LittleEndian.PutUint32(v2[16:20], 27)
	binary.LittleEndian.PutUint32(v2[20:24], 24)
	for _, frame := range [][]byte{makeTeamViewerPacket(102), v2} {
		for split := 1; split < len(frame); split++ {
			c := &core.ConversationInfo{Ident: "tv", CommunityID: "1:tv", Data: core.DataFragments{
				ftpFragment(string(frame[:split]), 10, false),
				ftpFragment(string(makeTeamViewerPacket(16)), 20, true),
				ftpFragment(string(frame[split:]), 30, false),
			}}
			var records []*types.Secret
			harvestTeamViewerConversation(c, func(s *types.Secret) { records = append(records, s) })
			if len(records) != 1 || records[0].Timestamp != 10 || records[0].CommunityID != c.CommunityID || records[0].Flow != c.Ident {
				t.Fatalf("split %d: lost framed auth/identity", split)
			}
			c.Data[2].(*core.StreamData).SkippedBytes = 1
			harvestTeamViewerConversation(c, func(*types.Secret) { t.Fatal("auth assembled across capture gap") })
		}
	}
	// A header inside a framed data payload is not another command.
	outer := append([]byte{0x17, 0x24, 90, 21, 0}, makeTeamViewerPacket(102)...)
	if teamviewerHarvesterFunc(outer, "data", time.Time{}) != nil {
		t.Fatal("data payload treated as authentication")
	}
	for _, invalid := range []string{"1724002d000000000000", "172466ffff00", "11306700ffffffff00000000000000001b00000018000000"} {
		data, _ := hex.DecodeString(invalid)
		if teamviewerHarvesterFunc(data, "invalid", time.Time{}) != nil {
			t.Fatal("invalid/truncated frame accepted")
		}
	}
}

func FuzzRound2SecretFraming(f *testing.F) {
	f.Add(makeTeamViewerPacket(102), uint16(3))
	f.Add([]byte("USER fixture\r\nPASS fixture\r\n"), uint16(5))
	f.Add([]byte{0x11, 0x30, 103, 0, 0xff, 0xff, 0xff, 0xff}, uint16(5))
	f.Fuzz(func(t *testing.T, data []byte, cut uint16) {
		if len(data) > 65536 {
			t.Skip()
		}
		split := min(int(cut), len(data))
		c := &core.ConversationInfo{Data: core.DataFragments{ftpFragment(string(data[:split]), 1, false), ftpFragment(string(data[split:]), 2, false)}}
		harvestTeamViewerConversation(c, func(*types.Secret) {})
		parseFTPAuth(c, func(*types.Secret) {})
		_ = teamviewerHarvesterFunc(data, "fuzz", time.Unix(1, 0))
	})
}

func TestRound2TeamViewerRealCommandOffset(t *testing.T) {
	// Command1 framing from random-wireshark-dissectors@3896597a/teamviewer.lua:
	// magic, command, LE payload length. Byte 3 is a length, not a command.
	data, _ := hex.DecodeString("172468040000000000")
	got := teamviewerHarvesterFunc(data, "auth", time.Unix(3, 4))
	if got == nil || got.User != "AUTH_RESULT" || got.Timestamp != 3000000004 {
		t.Fatalf("framed AUTH_RESULT was not retained: %v", got)
	}
}
