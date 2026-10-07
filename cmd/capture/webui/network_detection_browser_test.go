//go:build !appstore

package webui

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func TestNetworkDetectionBrowser(t *testing.T) {
	if os.Getenv("NETCAP_NETWORK_BROWSER") != "1" {
		t.Skip("requires built frontend and Chrome; NETCAP_NETWORK_BROWSER=1")
	}
	dir := t.TempDir()
	data, err := os.ReadFile("../../../internal/networkdetect/testdata/live/c2.alerts.json")
	if err != nil {
		t.Fatal(err)
	}
	var alerts []*types.Alert
	if err := json.Unmarshal(data, &alerts); err != nil {
		t.Fatal(err)
	}
	writer, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range alerts {
		if err := writer.WriteAlert(alert); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, NetworkDetectionSnapshotName), []byte(`{"schema":1,"events":101,"alerts":2,"overflow":0,"late":0,"streamGaps":0,"keys":1,"flows":0,"indicators":5}`), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	server := NewServer(address, dir, nil, "", false, false, false, nil, nil, false)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "scripts/qualify-network-detection.mjs", server.GetURL())
	command.Dir = "frontend"
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
