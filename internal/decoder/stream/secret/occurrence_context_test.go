package secret

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestEveryCredentialOccurrenceRetainsContext(t *testing.T) {
	old, oldConfig, oldCount := Decoder.Writer, decoderconfig.Instance, Decoder.NumRecordsWritten
	defer func() { Decoder.Writer, decoderconfig.Instance, Decoder.NumRecordsWritten = old, oldConfig, oldCount }()
	w := &observationWriter{}
	Decoder.Writer = w
	decoderconfig.Instance = &decoderconfig.Config{}
	for i := 0; i < 4; i++ {
		WriteSecret(&types.Secret{Timestamp: int64(i + 1), Flow: "192.0.2.1:50000->192.0.2.2:21", Service: "FTP", User: "analyst", Password: "fixture", Realm: []string{"a", "a", "b", "b"}[i], Uri: []string{"/first", "/second", "/first", "/second"}[i], AuthSuccessSet: i > 0, AuthSuccess: i == 3})
	}
	WriteSecret(&types.Secret{Timestamp: 5, Hash: "fixture-hash", Service: "hash-only"})
	if len(w.records) != 5 {
		t.Fatal("credential identity discarded occurrences", len(w.records))
	}
	for i, got := range w.records[:4] {
		if got.Timestamp != int64(i+1) || got.Uri == "" || got.Realm == "" || got.Src() != "192.0.2.1" || got.Dst() != "192.0.2.2" || got.AuthSuccessSet != (i > 0) || got.AuthSuccess != (i == 3) {
			t.Fatal("occurrence context lost", i)
		}
	}
}

func TestAuthenticationDecodeLogsExcludeWireInput(t *testing.T) {
	old := credLog
	defer func() { credLog = old }()
	core, logs := observer.New(zap.WarnLevel)
	credLog = zap.New(core)
	decodeSMTPLogin([][]byte{nil, []byte("private-credential!"), []byte("private-password!")}, "SMTP")
	decodeSMTPAuthPlain("private-credential!")
	imapHarvester.HarvesterFunc([]byte("a AUTHENTICATE PLAIN private-credential!\r\n"), "flow", time.Unix(1, 0))
	for _, entry := range logs.All() {
		b, _ := json.Marshal(entry.ContextMap())
		if strings.Contains(string(b), "private-") || strings.Contains(entry.Message, "private-") {
			t.Fatal("wire secret in logs")
		}
	}
	if logs.Len() < 2 {
		t.Fatal("negative path did not log")
	}
}
