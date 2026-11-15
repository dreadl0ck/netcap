package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
)

func TestStreamEvidenceBytesGapsAndTupleReuse(t *testing.T) {
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	payload = append(payload, []byte("\x1b[31mclient-looking bytes\x1b[0m")...)
	fragments := core.DataFragments{
		&core.StreamData{RawData: payload[:100], Dir: reassembly.TCPDirClientToServer, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 3)}},
		&core.StreamData{RawData: []byte("response"), Dir: reassembly.TCPDirServerToClient, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 4)}},
		&core.StreamData{Dir: reassembly.TCPDirClientToServer, SkippedBytes: 42, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 1)}},
		&core.StreamData{RawData: payload[100:], Dir: reassembly.TCPDirClientToServer, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 2)}},
	}
	out := t.TempDir()
	first, err := SaveStreamEvidence(out, "TCP", fragments, "same-tuple", time.Unix(1, 1), "community")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SaveStreamEvidence(out, "TCP", fragments, "same-tuple", time.Unix(1, 1), "community")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("tuple reuse appended evidence")
	}
	data, err := os.ReadFile(filepath.Join(first, "client.bin"))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("payload altered: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(first, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest StreamEvidenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	if manifest.Client.SHA256 != hex.EncodeToString(hash[:]) || manifest.Status != "gapped" || manifest.Spans[2].MissingBytes != 42 || manifest.Spans[3].Offset != 100 || manifest.Spans[3].TimestampNs != "1000000002" {
		t.Fatalf("gap/offset evidence lost: %+v", manifest)
	}
}

func TestStreamEvidenceUDPPreservesDatagramBoundaries(t *testing.T) {
	forward := gopacket.NewFlow(gopacket.EndpointType(4), []byte{1, 2}, []byte{3, 4})
	fragments := core.DataFragments{&core.StreamData{RawData: []byte("one"), Trans: forward}, &core.StreamData{RawData: []byte("two"), Trans: forward.Reverse()}, &core.StreamData{RawData: []byte("three"), Trans: forward}}
	dir, err := SaveStreamEvidence(t.TempDir(), "UDP", fragments, "udp", time.Unix(1, 0), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m StreamEvidenceManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Spans) != 3 || !m.Spans[0].Datagram || m.Spans[1].Direction != "server" || m.Spans[2].Offset != 3 {
		t.Fatalf("datagrams collapsed: %+v", m)
	}
}

func TestLocalRetentionOmissionIsDistinctFromNetworkLoss(t *testing.T) {
	fragments := core.DataFragments{&core.StreamData{RawData: []byte("prefix")},
		&core.StreamData{DiscardedBytes: 9, DiscardReason: "tcp-retained-payload-budget"},
		&core.StreamData{SkippedBytes: 42}, &core.StreamData{RawData: []byte("suffix")}}
	directory, err := SaveStreamEvidence(t.TempDir(), "TCP", fragments, "owned", time.Unix(1, 0), "owned")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest StreamEvidenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "locally-truncated" || manifest.Spans[1].DiscardedBytes != 9 || manifest.Spans[1].MissingBytes != 0 || manifest.Spans[1].DiscardReason != "tcp-retained-payload-budget" || manifest.Spans[2].MissingBytes != 42 {
		t.Fatalf("local and network loss were conflated: %+v", manifest)
	}
	if got := string(fragments.ContiguousBytes()); got != "prefix" {
		t.Fatal("local omission fabricated contiguous bytes", got)
	}
}

func TestLossOnlyConversationStillPublishesQualifiedStreamEvidence(t *testing.T) {
	previous := decoderconfig.Instance
	configuration := *decoderconfig.DefaultConfig
	configuration.Out, configuration.SaveConns = t.TempDir(), true
	decoderconfig.Instance = &configuration
	t.Cleanup(func() { decoderconfig.Instance = previous })
	fragments := core.DataFragments{&core.StreamData{DiscardedBytes: 64, DiscardReason: "tcp-retained-payload-budget"}}
	if err := SaveConversation("TCP", fragments, "owned", time.Unix(1, 0), gopacket.Flow{}, "owned"); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(configuration.Out, "stream-evidence", "stream-*", "manifest.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("discarded observations vanished: paths=%v err=%v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var manifest StreamEvidenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "locally-truncated" || manifest.Client.Length != 0 || manifest.Spans[0].DiscardedBytes != 64 {
		t.Fatalf("loss-only stream became empty clean evidence: %+v", manifest)
	}
}

func TestDatagramSourcePreservesLegacyBytesAndEvidence(t *testing.T) {
	previous, enricher := decoderconfig.Instance, DeviceEnricher
	defer func() { decoderconfig.Instance, DeviceEnricher = previous, enricher }()
	DeviceEnricher = nil
	forward := gopacket.NewFlow(gopacket.EndpointType(4), []byte{1, 2}, []byte{3, 4})
	fragments := core.DataFragments{&core.StreamData{RawData: []byte{0, 1, 2, 0xff}, Trans: forward, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 2)}}, &core.StreamData{RawData: []byte("reply"), Trans: forward.Reverse(), Dir: reassembly.TCPDirServerToClient, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 3)}}}
	var reference []byte
	var referenceManifest *StreamEvidenceManifest
	for _, source := range []bool{false, true} {
		cfg := decoderconfig.DefaultConfig.Clone()
		cfg.Out, cfg.SaveConns = t.TempDir(), true
		decoderconfig.Instance = cfg
		var err error
		if source {
			err = SaveDatagramConversation(core.SliceSource(fragments), "fixture", time.Unix(1, 2), forward, "id")
		} else {
			err = SaveConversation("UDP", fragments, "fixture", time.Unix(1, 2), forward, "id")
		}
		if err != nil {
			t.Fatal(err)
		}
		files, err := filepath.Glob(filepath.Join(cfg.Out, "udp", "*", "*.bin"))
		if err != nil || len(files) != 1 {
			t.Fatal(files, err)
		}
		data, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		manifests, _ := filepath.Glob(filepath.Join(cfg.Out, "stream-evidence", "stream-*", "manifest.json"))
		if len(manifests) != 1 {
			t.Fatal(manifests)
		}
		wire, err := os.ReadFile(manifests[0])
		if err != nil {
			t.Fatal(err)
		}
		var manifest StreamEvidenceManifest
		if err = json.Unmarshal(wire, &manifest); err != nil {
			t.Fatal(err)
		}
		if !source {
			reference, referenceManifest = data, &manifest
		} else if !bytes.Equal(reference, data) || !reflect.DeepEqual(*referenceManifest, manifest) {
			t.Fatal("datagram source changed payload or directional evidence")
		}
	}
}

type generatedEvidence struct {
	count  int
	sample func()
}

func (s generatedEvidence) Count() int64 { return int64(s.count) }
func (s generatedEvidence) Walk(yield func(core.DataFragment) bool) error {
	payload := make([]byte, 1024)
	for i := 0; i < s.count; i++ {
		if i == s.count/2 && s.sample != nil {
			s.sample()
		}
		if !yield(&core.StreamData{RawData: payload, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, int64(i))}}) {
			break
		}
	}
	return nil
}

func TestSourceEvidenceDoesNotRetainEverySpan(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak int64
	source := generatedEvidence{count: 50000, sample: func() {
		runtime.GC()
		var now runtime.MemStats
		runtime.ReadMemStats(&now)
		peak = max(peak, int64(now.HeapAlloc)-int64(before.HeapAlloc))
	}}
	dir, err := SaveSourceEvidence(t.TempDir(), "UDP", source, "fixture", time.Unix(1, 0), "id")
	if err != nil {
		t.Fatal(err)
	}
	if peak > 4<<20 {
		t.Fatalf("retained %d bytes while writing 50000 spans", peak)
	}
	wire, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest StreamEvidenceManifest
	if err = json.Unmarshal(wire, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Spans) != 50000 || manifest.Client.Length != 50000*1024 {
		t.Fatal("streaming evidence lost spans or bytes")
	}
	t.Logf("retained Go heap while writing 50000 evidence spans: %d bytes", peak)
}
