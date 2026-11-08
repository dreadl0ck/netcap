package stream

import (
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/types"
)

func TestRound2FTPSecretOn8884(t *testing.T) {
	matchingEnv(t)
	oldWriter, oldCount := secret.Decoder.Writer, secret.Decoder.NumRecordsWritten
	oldConfig := secret.GetHarvesterConfig()
	t.Cleanup(func() {
		secret.Decoder.Writer, secret.Decoder.NumRecordsWritten = oldWriter, oldCount
		_ = secret.InitializeHarvesters(oldConfig)
		secret.ResetSecretStore()
	})
	decoderconfig.Instance.Out = t.TempDir()
	decoderconfig.Instance.HarvesterPortFilter = true
	if err := secret.Decoder.PostInitFunc(); err != nil {
		t.Fatal(err)
	}
	w := &captureWriter{}
	secret.Decoder.Writer = w
	secret.ResetSecretStore()
	client := []byte("USER analyst\r\nPASS fixture\r\n")
	server := []byte("220 NzmxFtpd ready\r\n331 Password required\r\n230 Logged in\r\n")
	data := core.DataFragments{
		hygieneFragment([]byte("220 NzmxFtpd ready\r\n"), 1000000001, true),
		hygieneFragment([]byte("USER analyst\r\n"), 2000000002, false),
		hygieneFragment([]byte("331 Password required\r\n"), 3000000003, true),
		hygieneFragment([]byte("PASS fixture\r\n"), 4000000004, false),
		hygieneFragment([]byte("230 Logged in\r\n"), 5000000005, true),
	}
	c := &core.ConversationInfo{Data: data, Ident: "ftp-8884", CommunityID: "1:fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 45678, ServerPort: 8884, FirstClientPacket: time.Unix(1, 1)}
	for _, include := range []string{"", "Secret"} {
		decoderconfig.Instance.IncludeDecoders = include
		sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: 8884, PortClient: client, PortServer: server, ScanClient: client, ScanServer: server, Conversation: c})
		if !ok || sel.Name != "FTP" {
			t.Fatalf("include %q: FTP not selected: %+v", include, sel)
		}
		sel.Decoder.Decode()
		if len(w.records) != 1 {
			t.Fatalf("FTP/8884 emitted %d Secrets, want 1", len(w.records))
		}
		s := w.records[0].(*types.Secret)
		if s.User != "analyst" || s.Password != "fixture" || s.Timestamp != 2000000002 || s.CommunityID != c.CommunityID || s.Flow != c.Ident {
			t.Fatal("FTP observation lost credential or identity")
		}
	}
}
