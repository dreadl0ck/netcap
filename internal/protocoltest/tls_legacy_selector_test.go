package protocoltest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

func TestLegacyTLSDiscoveryUsesConfirmedTCPNamespace(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tshark")
	script := `#!/bin/sh
tuple=0
for arg in "$@"; do
  if [ "$arg" = tls.stream ]; then
    printf "tshark: Some fields aren't valid:\n tls.stream\n" >&2
    exit 1
  fi
  if [ "$arg" = ip.src ]; then tuple=1; fi
done
if [ "$tuple" = 1 ]; then
  printf '5\t192.0.2.1\t\t12345\t192.0.2.2\t\t443\n'
else
  printf '2\n5\n'
fi
`
	if err := os.WriteFile(tool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	rows, namespace, err := tlsDiscoveryRows(context.Background(), tool, "fixture.pcap", false)
	if err != nil || namespace != "tcp.stream" || strings.TrimSpace(rows) != "2\n5" {
		t.Fatal(rows, namespace, err)
	}
	rows, namespace, err = tlsDiscoveryRows(context.Background(), tool, "fixture.pcap", true)
	if err != nil || namespace != "tcp.stream" {
		t.Fatal(namespace, err)
	}
	id := streamutils.CalcCommunityIDTCP("192.0.2.1", "192.0.2.2", 12345, 443)
	if index, err := selectTLSStream(rows, id); err != nil || index != 5 {
		t.Fatal("legacy follow index was renumbered", index, err)
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nprintf 'capture read failed' >&2\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tlsDiscoveryRows(context.Background(), tool, "fixture.pcap", false); err == nil || !strings.Contains(err.Error(), "capture read failed") {
		t.Fatal("discovery diagnostic lost", err)
	}
}
