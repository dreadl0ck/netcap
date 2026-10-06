package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	behaviorcommand "github.com/dreadl0ck/netcap/internal/behavior/command"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/distributed"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

type behaviorDeliveryFailureLog struct{ failed chan struct{} }

func (w behaviorDeliveryFailureLog) Write(data []byte) (int, error) {
	if strings.Contains(string(data), "failed, retrying") {
		select {
		case w.failed <- struct{}{}:
		default:
		}
	}
	return len(data), nil
}

func behaviorTestIdentity(t *testing.T, root, name string) (tls.Certificate, string) {
	t.Helper()
	cert, key := filepath.Join(root, name+".crt"), filepath.Join(root, name+".key")
	fingerprint, err := distributed.GenerateIdentity(cert, key, name)
	if err != nil {
		t.Fatal(err)
	}
	id, err := distributed.LoadIdentity(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return id, fingerprint
}

func TestBehavioralAgentRetainsOfflineAlertsAndDeliversAfterReconnect(t *testing.T) {
	root := t.TempDir()
	agentID, agentFP := behaviorTestIdentity(t, root, "agent")
	serverID, serverFP := behaviorTestIdentity(t, root, "collector")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	failures := make(chan struct{}, 1)
	client, err := distributed.NewClient(distributed.ClientConfig{Addr: address, Identity: agentID, ServerFingerprint: serverFP,
		Hello: types.AgentHello{Source: "pcap", Version: "fixture"}, DialTimeout: 100 * time.Millisecond, AckTimeout: 100 * time.Millisecond,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, Logger: log.New(behaviorDeliveryFailureLog{failed: failures}, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = client.Close(ctx)
		}
	}()
	local := filepath.Join(root, "local")
	coll := &collector.Collector{}
	options := behaviorcommand.Options{Enabled: true, Sensor: agentFP, Learning: time.Nanosecond, MinSamples: 2, MaxFacts: 100,
		OnAlert: func(alert *types.Alert) {
			if err := enqueueBehaviorAlert(client, alert); err != nil {
				t.Error(err)
			}
		}}
	stop, err := behaviorcommand.StartOptions(options, coll, local, "fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stop() }()
	engine := coll.GetBehaviorEngine()
	fact := behavior.Fact{Scope: behavior.Scope{Sensor: agentFP, Interface: "pcap"}, Kind: "edge", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
	start := time.Unix(1700000000, 0)
	for _, at := range []time.Time{start, start.Add(time.Nanosecond)} {
		if err := engine.Observe(at, fact); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Change("approve", nil, "reviewed endpoint baseline"); err != nil {
		t.Fatal(err)
	}
	approved := engine.Snapshot()
	fact.DstIP = "192.0.2.3"
	if err := engine.Observe(start.Add(time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	stop, err = behaviorcommand.StartOptions(options, coll, local, "fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	engine = coll.GetBehaviorEngine()
	if state := engine.Snapshot(); state.Mode != behavior.Monitoring || state.BaselineID != approved.BaselineID || state.Version != approved.Version {
		t.Fatal("agent restart lost approved baseline")
	}
	fact.DstIP = "192.0.2.4"
	if err := engine.Observe(start.Add(2*time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if stats := client.Stats(); stats.Pending != 2 || stats.Acked != 0 {
		t.Fatalf("offline queue = %+v", stats)
	}
	select {
	case <-failures:
	case <-time.After(5 * time.Second):
		t.Fatal("transport never attempted delivery while collector was disconnected")
	}
	readAlerts := func(path string) []string {
		reader, err := netio.Open(path, 4096)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if _, err := reader.ReadHeader(); err != nil {
			t.Fatal(err)
		}
		var evidence []string
		for {
			var alert types.Alert
			err := reader.Next(&alert)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			evidence = append(evidence, alert.MatchedRecord)
		}
		return evidence
	}
	localEvidence := readAlerts(filepath.Join(local, "Alert.ncap.gz"))
	if len(localEvidence) != 2 {
		t.Fatal("local alerts were not durable before reconnect")
	}
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sink, err := distributed.NewSink(filepath.Join(root, "remote"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := distributed.NewServer(distributed.ServerConfig{Identity: serverID, Allowlist: distributed.Allowlist{agentFP: "endpoint"}, Sink: sink, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stats, err := client.Close(ctx)
	closed = true
	if err != nil || stats.Acked != 2 || stats.Pending != 0 || stats.Rejected != 0 || stats.Dropped != 0 {
		t.Fatalf("reconnected delivery = %+v, %v", stats, err)
	}
	files, err := server.Shutdown(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, distributed.ErrServerClosed) {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Type != types.Type_NC_Alert || files[0].Records != 2 {
		t.Fatalf("remote audit files = %+v", files)
	}
	remoteEvidence := readAlerts(files[0].Path)
	if len(remoteEvidence) != 2 || remoteEvidence[0] != localEvidence[0] || remoteEvidence[1] != localEvidence[1] {
		t.Fatal("transport changed or lost behavioral evidence")
	}
}
