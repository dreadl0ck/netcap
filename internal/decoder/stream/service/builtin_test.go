package service

import (
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"testing"
)

func TestMissingOptionalProbesKeepsServiceDecoderUsable(t *testing.T) {
	old, engine, inventory := resolvers.DataBaseFolderPath, signatureEngine.Load(), signatureInventory.Load()
	t.Cleanup(func() {
		resolvers.DataBaseFolderPath = old
		signatureEngine.Store(engine)
		signatureInventory.Store(inventory)
	})
	resolvers.DataBaseFolderPath = t.TempDir()
	if err := initServiceProbes(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ banner, name string }{
		{"SSH-2.0-OpenSSH_9.6\r\n", "ssh"}, {"HTTP/1.1 200 OK\r\nServer: fixture\r\nContent-Length: 0\r\n\r\n", "http"}, {"220 mail.example ESMTP ready\r\n", "smtp"}, {"220 fixture FTP server\r\n", "ftp"},
	} {
		r, ok := signatureEngine.Load().Identify([]byte(tc.banner), "tcp", "server-to-client")
		if !ok || r.Protocol != tc.name {
			t.Fatal(tc, r)
		}
	}
	for _, bad := range []string{"binary SSH-2.0-test\r\n", "220 ambiguous greeting\r\n", "HTTP/1.1 invalid\r\n\r\n", "SSH-2.0-\r\n"} {
		if _, ok := signatureEngine.Load().Identify([]byte(bad), "tcp", "server-to-client"); ok {
			t.Fatalf("claimed %q", bad)
		}
	}
}
