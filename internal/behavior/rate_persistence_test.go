package behavior

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestRateZeroWindowPCAPPersistence(t *testing.T) {
	var capture bytes.Buffer
	writer := pcapgo.NewWriterNanos(&capture)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, byte(2 + i/2)}, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: 50000, DstPort: 443, SYN: true, Seq: uint32(i)}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		packet := serializePacket(t, ethernet(), ip, tcp)
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(0, int64(i+1)), CaptureLength: len(packet.Data()), Length: len(packet.Data())}
		if err := writer.WritePacket(ci, packet.Data()); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(t.TempDir(), "near-epoch.pcap")
	if err := os.WriteFile(input, capture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	inputHash := sha256.Sum256(capture.Bytes())
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	e, sink := testEngine(t, 100)
	e.config.MinLearning, e.state.MinLearningNS = time.Nanosecond, 1
	for i := range 3 {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		if err := e.Observe(ci.Timestamp, PacketFacts(packet, testFact().Scope)...); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if err := e.Change("approve", nil, "reviewed original near-epoch capture"); err != nil {
				t.Fatal(err)
			}
		}
	}
	before := e.Snapshot()
	if len(before.Rates) != 1 || len(sink.alerts) == 0 {
		t.Fatalf("PCAP did not exercise rate and alert evidence: %+v", before)
	}
	for _, rate := range before.Rates {
		if rate.Start != 0 || rate.Packets != 3 || rate.Bytes == 0 {
			t.Fatalf("near-epoch rate = %+v", rate)
		}
	}
	alertEvidence := sink.alerts[0].MatchedRecord
	if err := e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(e.config, sink)
	if err != nil {
		t.Fatalf("reopen original PCAP baseline: %v", err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(before, reopened.Snapshot()) {
		t.Fatal("save/reopen changed counters, capture timestamps or approved evidence")
	}
	saved := filepath.Join(t.TempDir(), "saved-baseline.json")
	if err := SeedTemplate(e.config.Path, saved); err != nil {
		t.Fatalf("save validated PCAP baseline: %v", err)
	}
	savedBytes, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	var traffic Fact
	for _, rate := range before.Rates {
		traffic = rate.Fact
	}
	traffic.Bytes = 64
	if err := reopened.Observe(time.Unix(0, 4), traffic); err != nil {
		t.Fatal(err)
	}
	after := reopened.Snapshot()
	if rate := after.Rates[factID(traffic)]; rate.Start != 0 || rate.Packets != 4 || rate.Bytes != before.Rates[factID(traffic)].Bytes+64 {
		t.Fatalf("zero bucket treated as uninitialized after reopening: %+v", rate)
	}
	if after.BaselineID != before.BaselineID || after.Version != before.Version || !reflect.DeepEqual(after.Approved, before.Approved) || !reflect.DeepEqual(after.ApprovedRates, before.ApprovedRates) || sink.alerts[0].MatchedRecord != alertEvidence {
		t.Fatal("continued observation mutated approved baseline or historical alert evidence")
	}
	if data, err := os.ReadFile(saved); err != nil || !bytes.Equal(data, savedBytes) {
		t.Fatal("continued observation mutated saved evidence")
	}
	if data, err := os.ReadFile(input); err != nil || sha256.Sum256(data) != inputHash {
		t.Fatal("save path shifted or changed the source capture")
	}
	for _, ns := range []int64{int64(time.Minute), int64(time.Minute) - 1} {
		if err := reopened.Observe(time.Unix(0, ns), traffic); err != nil {
			t.Fatal(err)
		}
	}
	if rate := reopened.Snapshot().Rates[factID(traffic)]; rate.Start != int64(time.Minute) || rate.Packets != 1 || rate.Bytes != 64 {
		t.Fatalf("rollover/late packet corrupted rate bucket: %+v", rate)
	}
	if err := reopened.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if state, err := ReadSnapshot(e.config.Path); err != nil || !reflect.DeepEqual(state, reopened.Snapshot()) {
		t.Fatalf("rollover state did not persist: %v", err)
	}
}

func TestRatePersistenceWindowBoundaries(t *testing.T) {
	for _, window := range []time.Duration{time.Second, time.Minute, 24 * time.Hour} {
		for _, ns := range []int64{1, int64(window) - 1, int64(window), int64(window) + 1, math.MaxInt64} {
			t.Run(window.String()+"/"+time.Unix(0, ns).Format(time.RFC3339Nano), func(t *testing.T) {
				e, _ := testEngine(t, 10)
				e.state.Policy.WindowNS = int64(window)
				if err := e.Observe(time.Unix(0, ns), Fact{Scope: testFact().Scope, Kind: "traffic", SrcIP: "192.0.2.1", Bytes: 64}); err != nil {
					t.Fatal(err)
				}
				if err := e.Checkpoint(); err != nil {
					t.Fatal(err)
				}
				state, err := ReadSnapshot(e.config.Path)
				if err != nil || !reflect.DeepEqual(state, e.Snapshot()) {
					t.Fatalf("valid bucket rejected/changed: %v", err)
				}
			})
		}
	}
}

func TestRatePersistenceRejectsCorruption(t *testing.T) {
	e, _ := testEngine(t, 10)
	fact := Fact{Scope: testFact().Scope, Kind: "traffic", SrcIP: "192.0.2.1", Bytes: 64}
	if err := e.Observe(time.Unix(0, 1), fact); err != nil {
		t.Fatal(err)
	}
	id := factID(fact)
	valid, err := json.Marshal(e.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"negative start":      func(s *Snapshot) { r := s.Rates[id]; r.Start = -1; s.Rates[id] = r },
		"unaligned start":     func(s *Snapshot) { r := s.Rates[id]; r.Start = 1; s.Rates[id] = r },
		"wrong window":        func(s *Snapshot) { r := s.Rates[id]; r.Start = s.Policy.WindowNS; s.Rates[id] = r },
		"wrong key":           func(s *Snapshot) { s.Rates["wrong"] = s.Rates[id]; delete(s.Rates, id) },
		"missing observation": func(s *Snapshot) { delete(s.Observed, id) },
		"zero timestamp":      func(s *Snapshot) { o := s.Observed[id]; o.FirstSeen, o.LastSeen = 0, 0; s.Observed[id] = o },
		"negative timestamp":  func(s *Snapshot) { o := s.Observed[id]; o.FirstSeen, o.LastSeen = -1, -1; s.Observed[id] = o },
		"future timestamp":    func(s *Snapshot) { o := s.Observed[id]; o.LastSeen = 2; s.Observed[id] = o },
		"negative model":      func(s *Snapshot) { r := s.Rates[id]; r.Model.BytesMean = -1; s.Rates[id] = r },
		"invalid window":      func(s *Snapshot) { s.Policy.WindowNS = 0 },
		"rate bound":          func(s *Snapshot) { s.MaxFacts = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			var state Snapshot
			if err := json.Unmarshal(valid, &state); err != nil {
				t.Fatal(err)
			}
			mutate(&state)
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "corrupt.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadSnapshot(path); err == nil {
				t.Fatal("accepted corrupt rate state")
			}
			if err := SeedTemplate(path, filepath.Join(t.TempDir(), "saved.json")); err == nil {
				t.Fatal("saved corrupt rate state")
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
				t.Fatal("validation modified corrupt evidence")
			}
		})
	}
}

func TestRatePersistenceRejectsMalformedJSON(t *testing.T) {
	e, _ := testEngine(t, 10)
	if err := e.Observe(time.Unix(0, 1), Fact{Scope: testFact().Scope, Kind: "traffic", SrcIP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(e.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"string start":     strings.Replace(string(data), `"start":0`, `"start":"0"`, 1),
		"fractional start": strings.Replace(string(data), `"start":0`, `"start":0.5`, 1),
		"truncated":        string(data[:len(data)-1]),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "malformed.json")
			if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadSnapshot(path); err == nil {
				t.Fatal("accepted malformed snapshot")
			}
		})
	}
}

func TestRatePersistenceExistingPCAPSave(t *testing.T) {
	file, err := os.Open("testdata/qualification/discovery-dns/attack.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := testEngine(t, 10000)
	var packets int
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Observe(ci.Timestamp, PacketFacts(gopacket.NewPacket(data, reader.LinkType(), gopacket.Default), testFact().Scope)...); err != nil {
			t.Fatal(err)
		}
		packets++
	}
	before := e.Snapshot()
	if packets == 0 || len(before.Rates) == 0 {
		t.Fatal("existing PCAP did not exercise rates")
	}
	if err := e.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(t.TempDir(), "saved.json")
	if err := SeedTemplate(e.config.Path, saved); err != nil {
		t.Fatal(err)
	}
	state, err := ReadSnapshot(saved)
	if err != nil || !reflect.DeepEqual(before, state) {
		t.Fatalf("existing PCAP save changed state: %v", err)
	}
	t.Logf("saved %d original-timestamp PCAP packets, %d rate identities", packets, len(state.Rates))
}
