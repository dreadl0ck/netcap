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
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

type latencyAlertSink struct {
	writer  *rules.FileAlertWriter
	persist time.Duration
}

func (s *latencyAlertSink) WriteAlert(alert *types.Alert) error {
	start := time.Now()
	err := s.writer.WriteAlert(alert)
	s.persist += time.Since(start)
	return err
}

func TestBehavioralPacketToSSELatency(t *testing.T) {
	dir := t.TempDir()
	w, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	sink := &latencyAlertSink{writer: w}
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json"), MinLearning: time.Nanosecond, MinSamples: 2, MaxFacts: 10000}, sink)
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
	detection, persistence, delivery := make([]time.Duration, 0, 100), make([]time.Duration, 0, 100), make([]time.Duration, 0, 100)
	runStarted := time.Now()
	baselineFacts := len(engine.Snapshot().Approved)
	for i := range 100 {
		destination := fmt.Sprintf("198.51.100.%d", i+1)
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP(destination), Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(50000 + i), DstPort: 22, SYN: true, Seq: uint32(i + 1)}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp); err != nil {
			t.Fatal(err)
		}
		received := time.Now()
		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		beforePersist := sink.persist
		if err := engine.Observe(received, behavior.PacketFacts(packet, scope)...); err != nil {
			t.Fatal(err)
		}
		observed := time.Now()
		persist := sink.persist - beforePersist
		detection = append(detection, observed.Sub(received)-persist)
		persistence = append(persistence, persist)
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
				delivery = append(delivery, time.Since(observed))
				break
			}
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := latencies[94]
	for _, stage := range [][]time.Duration{detection, persistence, delivery} {
		sort.Slice(stage, func(i, j int) bool { return stage[i] < stage[j] })
	}
	duration := time.Since(runStarted)
	t.Logf("synthetic TCP SYN → passive decode → frozen-baseline detection → gzip+fsync → HTTP SSE; OS=%s arch=%s CPUs=%d Go=%s samples=100 sensors=1 baselineFacts=%d maxFacts=10000 duration=%s rate=%.2f packets/s captureDrops=0 (synthetic ingress) queueDrops=0 (synchronous ingress); p50=%s p95=%s max=%s; stage p95 decode+detector=%s persistence=%s delivery=%s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), baselineFacts, duration, 100/duration.Seconds(), latencies[49], p95, latencies[99], detection[94], persistence[94], delivery[94])
	if p95 >= time.Second {
		t.Fatalf("reference-workload p95 exceeded 1s: %s", p95)
	}
}
