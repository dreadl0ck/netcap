//go:build !appstore

package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBehavioralBrowserDelivery(t *testing.T) {
	if os.Getenv("NETCAP_BEHAVIOR_BROWSER") != "1" {
		t.Skip("requires pnpm install, pnpm build and Google Chrome; enable NETCAP_BEHAVIOR_BROWSER=1")
	}
	dir := t.TempDir()
	writer, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json"), MinLearning: time.Millisecond, MinSamples: 2, MaxFacts: 10000}, writer)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	scope := behavior.Scope{Sensor: "browser-fixture", Interface: "synthetic"}
	packetBytes := func(destination string, seq uint32) []byte {
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP(destination), Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(50000 + seq), DstPort: 443, SYN: true, Seq: seq}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	known := gopacket.NewPacket(packetBytes("192.0.2.2", 1), layers.LayerTypeIPv4, gopacket.Default)
	start := time.Now().Add(-time.Second)
	var inventory []behavior.Fact
	for i := range 997 {
		inventory = append(inventory, behavior.Fact{Scope: scope, Kind: "device", MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", byte(i>>8), byte(i))})
	}
	if err := engine.Observe(start, inventory...); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{start, start.Add(2 * time.Millisecond)} {
		if err := engine.Observe(at, behavior.PacketFacts(known, scope)...); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	server := NewServer(address, dir, nil, "", false, false, false, nil, nil, false)
	dc := config.DefaultConfig.Clone()
	dc.Out = dir
	coll := collector.New(collector.Config{DecoderConfig: dc})
	coll.SetBehaviorEngine(engine, scope)
	server.SetCollector(coll)
	server.SetLiveMode(true)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	var workloadOnce, stopOnce sync.Once
	var packets atomic.Uint64
	var workloadActive atomic.Bool
	var workloadStarted time.Time
	workloadStop, workloadDone := make(chan struct{}), make(chan struct{})
	stopWorkload := func() { stopOnce.Do(func() { close(workloadStop) }) }
	defer func() {
		stopWorkload()
		if workloadActive.Load() {
			<-workloadDone
		}
	}()
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			workloadOnce.Do(func() {
				workloadStarted = time.Now()
				workloadActive.Store(true)
				go func() {
					defer close(workloadDone)
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					data := packetBytes("192.0.2.2", 1)
					for {
						select {
						case <-workloadStop:
							return
						case <-ticker.C:
							for range 100 {
								at := time.Now()
								packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
								if err := engine.Observe(at, behavior.PacketFacts(packet, scope)...); err != nil {
									t.Error(err)
									return
								}
								packets.Add(1)
							}
							if packets.Load()%10000 == 0 {
								if err := engine.Checkpoint(); err != nil {
									t.Error(err)
									return
								}
							}
						}
					}
				}()
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"baselineFacts": len(engine.Snapshot().Approved)})
			return
		}
		if r.URL.Path == "/stop" {
			stopWorkload()
			<-workloadDone
			duration := time.Since(workloadStarted)
			state := engine.Snapshot()
			_ = json.NewEncoder(w).Encode(map[string]any{"backgroundPackets": packets.Load(), "backgroundDurationMS": duration.Milliseconds(), "backgroundPacketsPerSecond": float64(packets.Load()) / duration.Seconds(), "factOverflow": state.Overflow, "windowOverflow": state.WindowOverflow})
			return
		}
		var request struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.ID < 1 || request.ID > 100 {
			http.Error(w, "invalid sample", http.StatusBadRequest)
			return
		}
		destination := fmt.Sprintf("198.51.100.%d", request.ID)
		data := packetBytes(destination, uint32(request.ID+1))
		received := time.Now()
		packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
		if err := engine.Observe(received, behavior.PacketFacts(packet, scope)...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"receivedMS": float64(received.UnixNano()) / 1e6, "destination": destination})
	}))
	defer fixture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "scripts/qualify-behavior.mjs", server.GetURL(), fixture.URL)
	command.Dir = "frontend"
	output, err := command.CombinedOutput()
	t.Log(string(output))
	t.Logf("reference hardware: OS=%s arch=%s CPUs=%d Go=%s; synthetic synchronous ingress, 1000-fact approved baseline, no protocol-worker or kernel-capture workload", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	if err != nil {
		t.Fatalf("browser qualification: %v", err)
	}
}
