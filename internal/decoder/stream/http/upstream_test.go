package http

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Captures are losslessly compressed, not trimmed or rewritten. Hashes refer to
// the upstream PCAP bytes; the manifest pins source, command and expectations.
//
//go:embed testdata/round2.json
var round2Manifest []byte

type pcapHTTPFactory struct{ conversations []*core.ConversationInfo }
type pcapHTTPStream struct{ conversation *core.ConversationInfo }
type pcapContext struct{ info gopacket.CaptureInfo }

func (c pcapContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

func (f *pcapHTTPFactory) New(network, transport gopacket.Flow, _ reassembly.AssemblerContext) reassembly.Stream {
	srcPort, _ := strconv.Atoi(transport.Src().String())
	dstPort, _ := strconv.Atoi(transport.Dst().String())
	c := &core.ConversationInfo{ClientIP: network.Src().String(), ServerIP: network.Dst().String(), ClientPort: int32(srcPort), ServerPort: int32(dstPort), Ident: fmt.Sprintf("%s:%d->%s:%d", network.Src(), srcPort, network.Dst(), dstPort)}
	f.conversations = append(f.conversations, c)
	return &pcapHTTPStream{c}
}

func (*pcapHTTPStream) Accept(*layers.TCP, reassembly.TCPFlowDirection, reassembly.Sequence) bool {
	return true
}
func (*pcapHTTPStream) ReassemblyComplete(reassembly.AssemblerContext, gopacket.Flow, string) bool {
	return true
}
func (s *pcapHTTPStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	direction, _, _, skip := sg.Info()
	if skip != 0 {
		s.conversation.Data = append(s.conversation.Data, &core.StreamData{Dir: direction, SkippedBytes: skip, CaptureInformation: ac.GetCaptureInfo()})
	}
	sg.ForEach(func(data []byte, context reassembly.AssemblerContext) {
		s.conversation.Data = append(s.conversation.Data, &core.StreamData{Dir: direction, RawData: bytes.Clone(data), CaptureInformation: context.GetCaptureInfo()})
	})
}

func replayHTTPPCAP(t *testing.T, data []byte, removeSYN bool) *httpEvidenceWriter {
	t.Helper()
	var reader interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}
	var link layers.LinkType
	if bytes.HasPrefix(data, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		r, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		reader, link = r, r.LinkType()
	} else {
		r, err := pcapgo.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		reader, link = r, r.LinkType()
	}
	factory := &pcapHTTPFactory{}
	assembler := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
	for {
		wire, info, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(wire, link, gopacket.Default)
		if layer := packet.Layer(layers.LayerTypeTCP); layer != nil && packet.NetworkLayer() != nil {
			tcp := layer.(*layers.TCP)
			if removeSYN && tcp.SYN && !tcp.ACK {
				continue
			}
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, pcapContext{info})
		}
	}
	assembler.FlushAll()
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	defer func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count }()
	w := &httpEvidenceWriter{}
	Decoder.Writer, config.Instance = w, &config.Config{IncludePayloads: true}
	for _, conversation := range factory.conversations {
		(&httpReader{conversation: conversation}).Decode()
	}
	return w
}

func TestRound2UpstreamCaptures(t *testing.T) {
	var manifest struct {
		Revision string
		Fixtures []struct {
			Path, Issue, SHA256, Qualification, GzipBase64 string
			Requests                                       int
			Expected                                       []struct {
				Method, URL string
				Status      int32
				Stream      uint32
			}
		}
	}
	if err := json.Unmarshal(round2Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range manifest.Fixtures {
		t.Run(fixture.Path, func(t *testing.T) {
			compressed, err := base64.StdEncoding.DecodeString(fixture.GzipBase64)
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(compressed))
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(gz, 65537))
			if err != nil {
				t.Fatal(err)
			}
			_ = gz.Close()
			if len(data) > 65536 || fmt.Sprintf("%x", sha256.Sum256(data)) != fixture.SHA256 {
				t.Fatal("fixture digest mismatch")
			}
			var baseline []*types.HTTP
			for _, removeSYN := range []bool{false, true} {
				w := replayHTTPPCAP(t, data, removeSYN)
				if len(w.records) != len(fixture.Expected) {
					t.Fatalf("noSYN=%v got %d records, want %d", removeSYN, len(w.records), len(fixture.Expected))
				}
				requests, qualified := 0, false
				for i, record := range w.records {
					want := fixture.Expected[i]
					if record.Method != want.Method || record.URL != want.URL || record.StatusCode != want.Status || record.HTTP2StreamID != want.Stream {
						t.Fatalf("noSYN=%v record %d semantic mismatch: %v", removeSYN, i, record)
					}
					if record.Method != "" && record.StatusCode != 101 {
						requests++
					}
					if strings.Contains(strings.Join(record.ParseQualifications, ","), fixture.Qualification) {
						qualified = true
					}
					if record.Method != "" && record.Timestamp == 0 {
						t.Fatal("lost capture time")
					}
					t.Logf("noSYN=%v stream=%d method=%s status=%d url=%q qualification=%q", removeSYN, record.HTTP2StreamID, record.Method, record.StatusCode, record.URL, record.ReassemblyStatus)
					// Losing only SYN must preserve all visible message evidence,
					// endpoint attribution, timestamps, bodies and correlation.
					normalized := *record
					// Conversation IDs follow the first observed packet's direction.
					endpoints := strings.Split(record.Flow, "->")
					if len(endpoints) != 2 || record.Flow == "" {
						t.Fatalf("lost conversation identity: %q", record.Flow)
					}
					if endpoints[0] > endpoints[1] {
						endpoints[0], endpoints[1] = endpoints[1], endpoints[0]
					}
					normalized.Flow = strings.Join(endpoints, "->")
					var statuses []string
					for _, status := range strings.Split(record.ReassemblyStatus, ",") {
						if status != "unknown-initial-stream-loss" && status != "" {
							statuses = append(statuses, status)
						}
					}
					normalized.ReassemblyStatus = strings.Join(statuses, ",")
					if !removeSYN {
						baseline = append(baseline, &normalized)
					} else if !reflect.DeepEqual(baseline[i], &normalized) {
						before, after := reflect.ValueOf(*baseline[i]), reflect.ValueOf(normalized)
						for field := range before.NumField() {
							if !reflect.DeepEqual(before.Field(field).Interface(), after.Field(field).Interface()) {
								t.Errorf("SYN removal changed message %d field %s: before=%v after=%v", i, before.Type().Field(field).Name, before.Field(field), after.Field(field))
							}
						}
						t.FailNow()
					}
				}
				if requests != fixture.Requests || !qualified {
					t.Fatalf("noSYN=%v got requests=%d qualified=%v", removeSYN, requests, qualified)
				}
			}
		})
	}
}
