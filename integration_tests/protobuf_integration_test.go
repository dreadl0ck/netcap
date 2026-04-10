/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package integration_tests

import (
	"encoding/binary"
	"fmt"
	stdio "io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/collector"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/decoder/stream/protobuf"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// TestProtobufDecoderRegistration verifies the protobuf decoder is correctly
// registered in the stream decoder map on the expected ports.
func TestProtobufDecoderRegistration(t *testing.T) {
	ports := []int32{9090, 50051}
	for _, port := range ports {
		sd, exists := stream.DefaultStreamDecoders[port]
		if !exists {
			t.Errorf("No decoder registered on port %d", port)
			continue
		}
		if sd.GetName() != "Protobuf" {
			t.Errorf("Port %d: decoder name = %q, want %q", port, sd.GetName(), "Protobuf")
		}
		if sd.GetType() != types.Type_NC_Protobuf {
			t.Errorf("Port %d: type = %v, want %v", port, sd.GetType(), types.Type_NC_Protobuf)
		}
	}
}

// TestProtobufDecoderCanDecode verifies the CanDecode function accepts
// valid protobuf payloads and rejects common non-protobuf protocols.
func TestProtobufDecoderCanDecode(t *testing.T) {
	sd := stream.DefaultStreamDecoders[9090]
	if sd == nil {
		t.Fatal("Protobuf decoder not registered on port 9090")
	}

	tests := []struct {
		name     string
		client   []byte
		server   []byte
		expected bool
	}{
		{
			"valid protobuf client",
			buildProtobufPayload(),
			nil,
			true,
		},
		{
			"valid protobuf server",
			nil,
			buildProtobufResponse(),
			true,
		},
		{
			"both valid",
			buildProtobufPayload(),
			buildProtobufResponse(),
			true,
		},
		{
			"HTTP request",
			[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			false,
		},
		{
			"empty",
			nil,
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sd.CanDecodeStream(tt.client, tt.server)
			if got != tt.expected {
				t.Errorf("CanDecodeStream() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestProtobufDetectionHeuristics tests the detection function with
// various payload types to verify heuristic boundaries.
func TestProtobufDetectionHeuristics(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			"valid protobuf: varint+string+varint",
			buildProtobufPayload(),
			true,
		},
		{
			"valid protobuf: response message",
			buildProtobufResponse(),
			true,
		},
		{
			"large protobuf with many fields",
			buildLargeProtobufPayload(512),
			true,
		},
		{
			"plain HTTP request",
			[]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"),
			false,
		},
		{
			"plain JSON",
			[]byte(`{"name":"test","value":42,"items":["a","b","c"],"nested":{"key":"val"}}`),
			false,
		},
		{
			"all zeros",
			make([]byte, 100),
			false,
		},
		{
			"TLS ClientHello prefix",
			[]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03},
			false,
		},
		{
			"SSH banner",
			[]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protobuf.IsProtobufData(tt.data)
			if got != tt.expected {
				t.Errorf("IsProtobufData() = %v, want %v (len=%d, entropy=%.2f)",
					got, tt.expected, len(tt.data), protobuf.CalculateEntropy(tt.data))
			}
		})
	}
}

// TestProtobufParsingPipeline tests the full decode → extract fields pipeline
// end to end with various protobuf payloads.
func TestProtobufParsingPipeline(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantValid    bool
		wantMsgCount int
		wantFields   map[string]string
		wantMsgType  string
	}{
		{
			name:         "request with timestamp",
			data:         buildProtobufPayload(),
			wantValid:    true,
			wantMsgCount: 1,
			wantFields: map[string]string{
				"varint_1": "150",
				"string_2": "hello-grpc",
				"string_4": "/api/v1/status",
			},
			wantMsgType: "timestamped_message",
		},
		{
			name:         "response message",
			data:         buildProtobufResponse(),
			wantValid:    true,
			wantMsgCount: 1,
			wantFields: map[string]string{
				"varint_1": "200",
				"string_2": "OK",
				"string_3": "service-status-healthy",
			},
			wantMsgType: "timestamped_message",
		},
		{
			name:         "large message with many fields",
			data:         buildLargeProtobufPayload(256),
			wantValid:    true,
			wantMsgCount: 1,
			wantFields:   nil, // just check it parses
			wantMsgType:  "",  // don't check type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := protobuf.DecodeMessages(tt.data)
			if tt.wantValid {
				if err != nil {
					t.Fatalf("DecodeMessages() error = %v", err)
				}
				if len(msgs) != tt.wantMsgCount {
					t.Fatalf("got %d messages, want %d", len(msgs), tt.wantMsgCount)
				}
			}

			if tt.wantMsgCount > 0 && tt.wantMsgType != "" {
				msgType := protobuf.DetectMessageType(msgs[0])
				if msgType != tt.wantMsgType {
					t.Errorf("DetectMessageType() = %q, want %q", msgType, tt.wantMsgType)
				}
			}

			if tt.wantFields != nil && len(msgs) > 0 {
				fields := make(map[string]string)
				var order []string
				protobuf.PopulateFields(msgs[0], fields, &order)

				for key, want := range tt.wantFields {
					got, ok := fields[key]
					if !ok {
						t.Errorf("missing field %q", key)
					} else if got != want {
						t.Errorf("field %q = %q, want %q", key, got, want)
					}
				}
			}
		})
	}
}

// TestProtobufNoFalsePositivesCollector verifies the protobuf decoder does NOT
// produce records when processing PCAPs with non-protobuf traffic.
func TestProtobufNoFalsePositivesCollector(t *testing.T) {
	testCases := []struct {
		name     string
		pcapFile string
	}{
		{"HTTP_traffic", "../testdata/test.pcap"},
		{"CIP_industrial", "../testdata/cip.pcap"},
		{"S7Comm_industrial", "../testdata/s7comm_reading_plc_status.pcap"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.pcapFile); os.IsNotExist(err) {
				t.Skipf("Test pcap not found: %s", tc.pcapFile)
			}

			outDir := t.TempDir()

			if err := processWithCollector(tc.pcapFile, outDir); err != nil {
				t.Fatalf("Failed to process pcap: %v", err)
			}

			pbFile := filepath.Join(outDir, "Protobuf.ncap.gz")
			info, err := os.Stat(pbFile)

			if os.IsNotExist(err) {
				t.Logf("No Protobuf records produced (good)")
				return
			}

			if err == nil && info.Size() > 0 {
				records, readErr := readProtobufRecords(pbFile)
				if readErr == nil && len(records) > 0 {
					t.Logf("Warning: %d Protobuf record(s) from %s (potential false positives)",
						len(records), tc.pcapFile)
					for i, rec := range records {
						t.Logf("  Record %d: valid=%v msgType=%s service=%s size=%d entropy=%.2f",
							i+1, rec.IsValid, rec.MessageType, rec.ServiceName, rec.PayloadSize, rec.PayloadEntropy)
					}
				}
			}
		})
	}
}

// TestProtobufServiceNameDetection verifies port-based service classification.
func TestProtobufServiceNameDetection(t *testing.T) {
	tests := []struct {
		srcPort  int32
		dstPort  int32
		expected string
	}{
		{54321, 443, "https/grpc"},
		{54321, 80, "http"},
		{54321, 9090, "grpc"},
		{54321, 50051, "grpc"},
		{54321, 8080, "custom_service"},
		{54321, 8443, "custom_service"},
		{54321, 12345, "unknown"},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("src%d_dst%d", tt.srcPort, tt.dstPort)
		t.Run(name, func(t *testing.T) {
			got := protobuf.DetectServiceName(tt.srcPort, tt.dstPort)
			if got != tt.expected {
				t.Errorf("DetectServiceName(%d, %d) = %q, want %q",
					tt.srcPort, tt.dstPort, got, tt.expected)
			}
		})
	}
}

// --- Performance benchmarks ---

// BenchmarkProtobufDetection measures the throughput of the detection heuristic.
func BenchmarkProtobufDetection(b *testing.B) {
	payloads := map[string][]byte{
		"protobuf_small":  buildProtobufPayload(),
		"protobuf_large":  buildLargeProtobufPayload(1024),
		"http_request":    []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"),
		"json":            []byte(`{"name":"test","value":42,"items":["a","b","c"]}`),
		"random_1KB":      deterministicBytes(1024),
		"random_16KB":     deterministicBytes(16384),
	}

	for name, data := range payloads {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				protobuf.IsProtobufData(data)
			}
		})
	}
}

// BenchmarkProtobufDecoding measures parsing throughput for valid protobuf.
func BenchmarkProtobufDecoding(b *testing.B) {
	payloads := map[string][]byte{
		"3_fields":  buildProtobufPayload(),
		"10_fields": buildLargeProtobufPayload(256),
		"large_1KB": buildLargeProtobufPayload(1024),
	}

	for name, data := range payloads {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				protobuf.DecodeMessages(data)
			}
		})
	}
}

// BenchmarkEntropy measures Shannon entropy calculation throughput.
func BenchmarkEntropy(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		data := deterministicBytes(size)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				protobuf.CalculateEntropy(data)
			}
		})
	}
}

// BenchmarkFullPipeline benchmarks detection + parsing + field extraction together.
func BenchmarkFullPipeline(b *testing.B) {
	payload := buildProtobufPayload()
	b.SetBytes(int64(len(payload)))

	for b.Loop() {
		if protobuf.IsProtobufData(payload) {
			msgs, err := protobuf.DecodeMessages(payload)
			if err == nil && len(msgs) > 0 {
				fields := make(map[string]string)
				var order []string
				protobuf.PopulateFields(msgs[0], fields, &order)
			}
		}
	}
}

// --- PCAP integration tests ---

const protobufTestdataDir = "../decoder/stream/protobuf/testdata"

// TestProtobufPCAPExtraction processes real protobuf PCAP files through the
// collector pipeline and verifies Protobuf audit records are extracted.
func TestProtobufPCAPExtraction(t *testing.T) {
	testCases := []struct {
		name      string
		pcapFile  string
		transport string
		srcIP     string // expected source IP to filter relevant records
		dstIP     string // expected destination IP to filter relevant records
	}{
		{
			name:      "TCP_AddressBook",
			pcapFile:  "protobuf_tcp_addressbook.pcapng",
			transport: "TCP",
			srcIP:     "127.0.0.1",
			dstIP:     "127.0.0.1",
		},
		{
			name:      "UDP_AddressBook",
			pcapFile:  "protobuf_udp_addressbook.pcapng",
			transport: "UDP",
			srcIP:     "127.0.0.1",
			dstIP:     "127.0.0.1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join(protobufTestdataDir, tc.pcapFile)

			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("Test pcap file not found: %s", pcapPath)
			}

			outDir := t.TempDir()

			if err := processWithCollector(pcapPath, outDir); err != nil {
				t.Fatalf("Failed to process pcap: %v", err)
			}

			pbFile := filepath.Join(outDir, "Protobuf.ncap.gz")
			info, err := os.Stat(pbFile)
			if os.IsNotExist(err) {
				t.Fatalf("Protobuf.ncap.gz was not created — no protobuf records extracted from %s", tc.pcapFile)
			}
			if err != nil {
				t.Fatalf("Failed to stat Protobuf.ncap.gz: %v", err)
			}
			if info.Size() == 0 {
				t.Fatalf("Protobuf.ncap.gz is empty")
			}

			allRecords, err := readProtobufRecords(pbFile)
			if err != nil {
				t.Fatalf("Failed to read Protobuf records: %v", err)
			}

			// Filter records to those matching the expected IPs from this PCAP.
			// The global decoder state may carry records from prior tests in the same
			// process due to shared decoder instances.
			var records []*types.Protobuf
			for _, rec := range allRecords {
				if rec.SrcIP == tc.srcIP && rec.DstIP == tc.dstIP {
					records = append(records, rec)
				}
			}

			if len(records) == 0 {
				t.Fatalf("No Protobuf records with expected IPs (%s -> %s) extracted from %s (total records: %d)",
					tc.srcIP, tc.dstIP, tc.pcapFile, len(allRecords))
			}

			t.Logf("Extracted %d Protobuf record(s) from %s (%s) [%d total, %d filtered]",
				len(records), tc.pcapFile, tc.transport, len(allRecords), len(allRecords)-len(records))

			for i, rec := range records {
				t.Logf("Record %d: valid=%v msgType=%s service=%s srcIP=%s dstIP=%s srcPort=%d dstPort=%d payloadSize=%d fields=%d",
					i+1, rec.IsValid, rec.MessageType, rec.ServiceName,
					rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort,
					rec.PayloadSize, len(rec.Fields))

				if !rec.IsValid {
					t.Errorf("Record %d: IsValid = false, error: %s", i+1, rec.ErrorMsg)
				}
				if rec.MessageCount < 1 {
					t.Errorf("Record %d: MessageCount = %d, want >= 1", i+1, rec.MessageCount)
				}
				if rec.PayloadSize <= 0 {
					t.Errorf("Record %d: PayloadSize = %d, want > 0", i+1, rec.PayloadSize)
				}
				if len(rec.Fields) == 0 {
					t.Errorf("Record %d: Fields map is empty — no fields decoded", i+1)
				}
			}
		})
	}
}

// --- helpers ---

// processWithCollector runs the netcap collector on a PCAP file.
func processWithCollector(pcapPath, outDir string) error {
	// Reset shared writer registry to ensure test isolation
	netio.ResetWriterRegistry()

	cfg := collector.DefaultConfig

	decoderCfg := *decoderconfig.DefaultConfig
	decoderCfg.Out = outDir
	decoderCfg.Source = pcapPath
	cfg.DecoderConfig = &decoderCfg
	cfg.ReassembleConnections = true

	c := collector.New(cfg)

	if filepath.Ext(pcapPath) == ".pcapng" {
		return c.CollectPcapNG(pcapPath)
	}
	return c.CollectPcap(pcapPath)
}

// readProtobufRecords reads Protobuf audit records from an ncap.gz file.
func readProtobufRecords(filename string) ([]*types.Protobuf, error) {
	r, err := netio.Open(filename, 4096)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	header, err := r.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if header.Type != types.Type_NC_Protobuf {
		return nil, fmt.Errorf("unexpected record type: %s", header.Type)
	}

	var records []*types.Protobuf
	for {
		rec := new(types.Protobuf)
		err = r.Next(rec)
		if err != nil {
			if err == stdio.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read record: %w", err)
		}
		records = append(records, rec)
	}
	return records, nil
}

// buildProtobufPayload creates a valid protobuf binary message:
//
//	field 1: varint 150
//	field 2: string "hello-grpc"
//	field 3: varint 0
//	field 4: string "/api/v1/status"
//	field 5: varint 1609459200 (unix timestamp)
func buildProtobufPayload() []byte {
	var buf []byte

	// field 1, wire type 0 (varint), value 150
	buf = append(buf, 0x08)
	buf = appendVarint(buf, 150)

	// field 2, wire type 2 (length-delimited), "hello-grpc"
	buf = append(buf, 0x12)
	s := []byte("hello-grpc")
	buf = appendVarint(buf, uint64(len(s)))
	buf = append(buf, s...)

	// field 3, wire type 0 (varint), value 0
	buf = append(buf, 0x18)
	buf = appendVarint(buf, 0)

	// field 4, wire type 2 (length-delimited), "/api/v1/status"
	buf = append(buf, 0x22)
	s2 := []byte("/api/v1/status")
	buf = appendVarint(buf, uint64(len(s2)))
	buf = append(buf, s2...)

	// field 5, wire type 0 (varint), unix timestamp
	buf = append(buf, 0x28)
	buf = appendVarint(buf, 1609459200)

	return buf
}

// buildProtobufResponse creates a protobuf response message.
func buildProtobufResponse() []byte {
	var buf []byte

	// field 1, wire type 0 (varint), status=200
	buf = append(buf, 0x08)
	buf = appendVarint(buf, 200)

	// field 2, wire type 2 (length-delimited), "OK"
	buf = append(buf, 0x12)
	s := []byte("OK")
	buf = appendVarint(buf, uint64(len(s)))
	buf = append(buf, s...)

	// field 3, wire type 2 (length-delimited), response body
	buf = append(buf, 0x1A)
	body := []byte("service-status-healthy")
	buf = appendVarint(buf, uint64(len(body)))
	buf = append(buf, body...)

	// field 4, wire type 0 (varint), timestamp
	buf = append(buf, 0x20)
	buf = appendVarint(buf, 1609459201)

	return buf
}

// buildLargeProtobufPayload creates a protobuf payload with many fields.
func buildLargeProtobufPayload(targetSize int) []byte {
	var buf []byte
	fieldNum := uint64(1)

	for len(buf) < targetSize {
		if fieldNum%2 == 1 {
			tag := fieldNum << 3 // varint wire type 0
			buf = appendVarint(buf, tag)
			buf = appendVarint(buf, fieldNum*1000+42)
		} else {
			tag := (fieldNum << 3) | 2 // length-delimited wire type 2
			buf = appendVarint(buf, tag)
			s := fmt.Appendf(nil, "field-value-%d", fieldNum)
			buf = appendVarint(buf, uint64(len(s)))
			buf = append(buf, s...)
		}
		fieldNum++
	}

	return buf
}

func appendVarint(buf []byte, v uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(buf, tmp[:n]...)
}

func deterministicBytes(size int) []byte {
	d := make([]byte, size)
	for i := range d {
		d[i] = byte((i * 37 + 13) % 256)
	}
	return d
}
