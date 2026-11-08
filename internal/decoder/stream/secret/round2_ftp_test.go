package secret

import (
	"fmt"
	"strings"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func ftpFragment(data string, at int64, server bool) *core.StreamData {
	dir := reassembly.TCPDirClientToServer
	if server {
		dir = reassembly.TCPDirServerToClient
	}
	return &core.StreamData{RawData: []byte(data), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, at)}, Dir: dir}
}

func TestRound2FTPFragmentedLogin(t *testing.T) {
	const command = "USER analyst\r\nPASS fixture with spaces\r\n"
	for split := 1; split < len(command); split++ {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			c := &core.ConversationInfo{Ident: "ftp", CommunityID: "1:owned", ServerPort: 8884, Data: core.DataFragments{
				ftpFragment("220-FTP ready\r\nUSER decoy\r\n220 Ready\r\n", 1, true),
				ftpFragment(command[:split], 20, false), ftpFragment(command[split:], 30, false),
				ftpFragment("230 Logged in\r\n", 40, true),
			}}
			var records []*types.Secret
			parseFTPAuth(c, func(s *types.Secret) { records = append(records, s) })
			if len(records) != 1 {
				t.Fatalf("got %d secrets", len(records))
			}
			s := records[0]
			if s.User != "analyst" || s.Password != "fixture with spaces" || s.Timestamp != 20 || s.CommunityID != c.CommunityID || s.Flow != c.Ident || !s.AuthSuccessSet || !s.AuthSuccess {
				t.Fatalf("wrong login semantics: %+v", s)
			}
		})
	}
}

func TestRound2FTPBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  core.DataFragments
		count int
	}{
		{"accepted AUTH TLS", core.DataFragments{ftpFragment("AUTH TLS\r\n", 1, false), ftpFragment("234 Proceed\r\n", 2, true), ftpFragment("USER forged\r\nPASS forged\r\n", 3, false)}, 0},
		{"unanswered AUTH", core.DataFragments{ftpFragment("AUTH TLS\r\nUSER forged\r\nPASS forged\r\n", 1, false)}, 0},
		{"failed AUTH permits plaintext", core.DataFragments{ftpFragment("AUTH TLS\r\n", 1, false), ftpFragment("534 Rejected\r\n", 2, true), ftpFragment("USER analyst\r\nPASS fixture\r\n", 3, false)}, 1},
		{"implicit TLS", core.DataFragments{ftpFragment("\x16\x03\x03\x00\x30USER forged\r\nPASS forged\r\n", 1, false)}, 0},
		{"rejected USER", core.DataFragments{ftpFragment("USER analyst\r\n", 1, false), ftpFragment("530 Rejected\r\n", 2, true), ftpFragment("PASS fixture\r\n", 3, false)}, 0},
		{"reinit clears username", core.DataFragments{ftpFragment("USER analyst\r\nREIN\r\nPASS fixture\r\n", 1, false)}, 0},
		{"server bytes are not commands", core.DataFragments{ftpFragment("220-FTP\r\nUSER forged\r\nPASS forged\r\n220 Ready\r\n", 1, true)}, 0},
		{"line budget", core.DataFragments{ftpFragment("USER "+strings.Repeat("a", 8192)+"\r\nPASS forged\r\n", 1, false)}, 0},
		{"incomplete password", core.DataFragments{ftpFragment("USER analyst\r\nPASS truncated", 1, false)}, 0},
		{"binary control byte", core.DataFragments{ftpFragment("USER analyst\r\nPASS forged\x00\r\n", 1, false)}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			parseFTPAuth(&core.ConversationInfo{Data: tc.data}, func(*types.Secret) { count++ })
			if count != tc.count {
				t.Fatalf("got %d, want %d", count, tc.count)
			}
		})
	}
	for _, gap := range []int{-1, 1, 4096} {
		f := ftpFragment("PASS fixture\r\n", 2, false)
		f.SkippedBytes = gap
		parseFTPAuth(&core.ConversationInfo{Data: core.DataFragments{ftpFragment("USER analyst\r\n", 1, false), f}}, func(*types.Secret) { t.Errorf("paired across gap %d", gap) })
	}
	f := ftpFragment("USER analyst\r\nPASS fixture\r\n", 0, false)
	f.SkippedBytes = -1
	count := 0
	parseFTPAuth(&core.ConversationInfo{Data: core.DataFragments{f}}, func(s *types.Secret) {
		count++
		if s.Timestamp != 0 {
			t.Fatal("epoch zero replaced")
		}
	})
	if count != 1 {
		t.Fatal("initial unknown gap discarded observed login")
	}
	f.DiscardedBytes = 1
	parseFTPAuth(&core.ConversationInfo{Data: core.DataFragments{f}}, func(*types.Secret) { t.Fatal("discarded bytes admitted as complete login") })
}

func TestRound2FTPOutcomeQualification(t *testing.T) {
	for _, tc := range []struct {
		reply        string
		set, success bool
	}{
		{"230 Logged in\r\n", true, true},
		{"530 Denied\r\n", true, false},
		{"", false, false},
		{"230-Welcome\r\n530 text inside multiline\r\n", false, false},
		{"230-Welcome\r\n530 text inside multiline\r\n230 Done\r\n", true, true},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			c := &core.ConversationInfo{Data: core.DataFragments{ftpFragment("USER analyst\r\nPASS fixture\r\n", 1, false), ftpFragment(tc.reply, 2, true)}}
			count := 0
			parseFTPAuth(c, func(s *types.Secret) {
				count++
				if s.AuthSuccessSet != tc.set || s.AuthSuccess != tc.success {
					t.Fatalf("unqualified outcome: %+v", s)
				}
			})
			if count != 1 {
				t.Fatalf("got %d logins", count)
			}
		})
	}
}

func TestRound2FTPHasOneEmissionPath(t *testing.T) {
	oldWriter, oldCount, oldConfig, oldUse := Decoder.Writer, Decoder.NumRecordsWritten, decoderconfig.Instance, useHarvesters
	oldHarvesters, oldPorts, oldMapping, oldHC := tcpConnectionHarvesters, harvesterPorts, harvesterPortMapping, harvesterConfig
	t.Cleanup(func() {
		Decoder.Writer, Decoder.NumRecordsWritten, decoderconfig.Instance, useHarvesters = oldWriter, oldCount, oldConfig, oldUse
		tcpConnectionHarvesters, harvesterPorts, harvesterPortMapping, harvesterConfig = oldHarvesters, oldPorts, oldMapping, oldHC
	})
	w := &observationWriter{}
	Decoder.Writer, useHarvesters = w, true
	decoderconfig.Instance = &decoderconfig.Config{HarvesterBannerSize: 4096, HarvesterPortFilter: true}
	if err := InitializeHarvesters(&HarvestersConfigFile{Harvesters: []HarvesterConfig{{Name: "FTP", Enabled: true, Ports: []int{21}}}}); err != nil {
		t.Fatal(err)
	}
	c := &core.ConversationInfo{Ident: "ftp-8884", CommunityID: "cid", ClientPort: 50000, ServerPort: 8884, Data: core.DataFragments{
		ftpFragment("220 FTP ready\r\n", 1, true), ftpFragment("USER analyst\r\n", 2, false),
		ftpFragment("331 Password\r\n", 3, true), ftpFragment("PASS fixture\r\n", 4, false), ftpFragment("230 Success\r\n", 5, true),
	}}
	banner := []byte("220 FTP ready\r\nUSER analyst\r\n331 Password\r\nPASS fixture\r\n")
	transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0xc3, 0x50}, []byte{0, 21})
	RunHarvesters(banner, transport, c.Ident, c.FirstClientPacket, c.CommunityID)
	if len(w.records) != 0 {
		t.Fatal("legacy banner path still emits FTP")
	}
	HarvestFTPConversation(c)
	if len(w.records) != 1 || w.records[0].Timestamp != 2 || w.records[0].CommunityID != "cid" {
		t.Fatalf("duplicates or lost identity: %v", w.records)
	}
	c.Ident = "ftp-8884-second-flow"
	HarvestFTPConversation(c)
	if len(w.records) != 2 || w.records[1].Flow != c.Ident {
		t.Fatal("same credentials on a distinct flow were discarded")
	}
	_ = InitializeHarvesters(&HarvestersConfigFile{})
	c.Ident = "disabled"
	HarvestFTPConversation(c)
	if len(w.records) != 2 {
		t.Fatal("disabled FTP harvester emitted")
	}
}
