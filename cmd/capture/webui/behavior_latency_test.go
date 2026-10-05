package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/rules"
)

func TestBehavioralPacketToSSELatency(t *testing.T) {
	dir := t.TempDir()
	w, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json"), MinLearning: time.Nanosecond, MinSamples: 2, MaxFacts: 10000}, w)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	scope := behavior.Scope{Sensor: "latency-fixture", Interface: "pcap"}
	known := behavior.Fact{Scope: scope, Kind: "edge", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
	start := time.Now().Add(-time.Second)
	if err := engine.Observe(start, known); err != nil {
		t.Fatal(err)
	}
	if err := engine.Observe(start.Add(time.Nanosecond), known); err != nil {
		t.Fatal(err)
	}
	if err := engine.Change("approve", nil, "latency fixture"); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir, baseOutDir: dir, shutdownChan: make(chan struct{})}
	server := httptest.NewServer(http.HandlerFunc(s.handleAlertsStream))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if event := readTestSSE(t, reader); event.event != "connected" {
		t.Fatal("stream did not connect")
	}
	latencies := make([]time.Duration, 0, 100)
	for i := range 100 {
		destination := fmt.Sprintf("198.51.100.%d", i+1)
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP(destination), Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(50000 + i), DstPort: 22, SYN: true, Seq: uint32(i + 1)}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp); err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		received := time.Now()
		if err := engine.Observe(received, behavior.PacketFacts(packet, scope)...); err != nil {
			t.Fatal(err)
		}
		for {
			event := readTestSSE(t, reader)
			if event.event != "alert" {
				continue
			}
			var alert AlertResponse
			if err := json.Unmarshal([]byte(event.data), &alert); err != nil {
				t.Fatal(err)
			}
			if alert.RuleName == "baseline.new-service" && alert.DstIP == destination {
				latencies = append(latencies, time.Since(received))
				break
			}
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := latencies[94]
	t.Logf("synthetic TCP SYN → passive decode → frozen-baseline detection → gzip+fsync → HTTP SSE; samples=100, sensors=1, maxFacts=10000, p50=%s p95=%s max=%s", latencies[49], p95, latencies[99])
	if p95 >= time.Second {
		t.Fatalf("reference-workload p95 exceeded 1s: %s", p95)
	}
}
