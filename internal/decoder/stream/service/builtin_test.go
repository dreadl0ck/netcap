package service

import (
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestMissingOptionalProbesKeepsServiceDecoderUsable(t *testing.T) {
	old, probes, categories := resolvers.DataBaseFolderPath, serviceProbes, serviceProbeCategories
	t.Cleanup(func() { resolvers.DataBaseFolderPath, serviceProbes, serviceProbeCategories = old, probes, categories })
	resolvers.DataBaseFolderPath = t.TempDir()
	if err := initServiceProbes(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ banner, name string }{
		{"SSH-2.0-OpenSSH_9.6\r\n", "ssh"}, {"HTTP/1.1 200 OK\r\nServer: fixture\r\nContent-Length: 0\r\n\r\n", "http"}, {"220 mail.example ESMTP ready\r\n", "smtp"}, {"220 fixture FTP server\r\n", "ftp"},
	} {
		s := &service{Service: &types.Service{}}
		if !identifyBuiltinBanner(s, []byte(tc.banner)) || s.Name != tc.name {
			t.Fatal(tc, s)
		}
	}
	for _, bad := range []string{"binary SSH-2.0-test\r\n", "220 ambiguous greeting\r\n", "HTTP/1.1 invalid\r\n\r\n", "SSH-2.0-\r\n"} {
		if identifyBuiltinBanner(&service{Service: &types.Service{}}, []byte(bad)) {
			t.Fatalf("claimed %q", bad)
		}
	}
}
