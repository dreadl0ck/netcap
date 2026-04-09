/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package protobuf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
)

var pbLog = zap.NewNop()

// Decoder for generic Protocol Buffer wire format detection and analysis.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Protobuf,
	Name:        "Protobuf",
	Description: "Generic Protocol Buffer wire format decoder for unknown protobuf traffic",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		pbLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"protobuf",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		return IsProtobufData(client) || IsProtobufData(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return pbLog.Sync()
	},
	Factory: &protobufReader{},
	Typ:     core.TCP,
}

// Field represents a single decoded protobuf field, preserving wire order.
type Field struct {
	Number uint64 // protobuf field number
	Type   string // "varint", "fixed64", "string", "bytes", "nested", "fixed32"
	Value  string // string representation of the value
}

// protobufReader implements core.StreamDecoderFactory and core.StreamDecoderInterface.
type protobufReader struct {
	conversation *core.ConversationInfo
	mu           sync.Mutex
}

// New creates a new protobuf reader instance for a conversation.
func (r *protobufReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &protobufReader{
		conversation: conversation,
	}
}

// Decode processes the conversation data and extracts protobuf messages.
func (r *protobufReader) Decode() {
	if Decoder.Writer == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	streamutils.DecodeConversation(
		r.conversation.Ident,
		r.conversation.Data,
		func(b *bufio.Reader) error {
			return r.processData(b, true)
		},
		func(b *bufio.Reader) error {
			return r.processData(b, false)
		},
	)
}

// processData reads all available data from a direction and attempts protobuf parsing.
// Returns io.EOF when no data remains, which signals DecodeConversation to stop calling.
func (r *protobufReader) processData(b *bufio.Reader, isClient bool) error {
	data, err := io.ReadAll(b)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return io.EOF
	}

	var ts int64
	if isClient {
		ts = r.conversation.FirstClientPacket.UnixNano()
	} else {
		ts = r.conversation.FirstServerPacket.UnixNano()
	}

	var e float64
	if decoderconfig.Instance.CalculateEntropy {
		e = CalculateEntropy(data)
	}

	pb := &types.Protobuf{
		Timestamp:       ts,
		SrcIP:           r.conversation.ClientIP,
		DstIP:           r.conversation.ServerIP,
		SrcPort:         r.conversation.ClientPort,
		DstPort:         r.conversation.ServerPort,
		PayloadSize:     int32(len(data)),
		PayloadEntropy:  e,
		RawPayload:      data,
		Fields:          make(map[string]string),
		DetectionMethod: "heuristic",
	}

	messages, parseErr := DecodeMessages(data)
	if parseErr != nil {
		pb.IsValid = false
		pb.ErrorMsg = parseErr.Error()
		pb.MessageCount = 0
	} else {
		pb.IsValid = true
		pb.MessageCount = int32(len(messages))

		for i, msg := range messages {
			if i == 0 {
				pb.MessageType = DetectMessageType(msg)
				pb.ServiceName = DetectServiceName(r.conversation.ClientPort, r.conversation.ServerPort)
			}
			PopulateFields(msg, pb.Fields, &pb.FieldOrder)
		}
	}

	writeErr := Decoder.Writer.Write(pb)
	if writeErr != nil {
		pbLog.Debug("failed to write protobuf audit record", zap.Error(writeErr))
	}

	return nil
}

// --- Protobuf wire format detection and parsing ---

const (
	maxFieldsPerMessage = 100
	maxMessagesPerParse = 10
	maxFieldSize        = 1 << 20 // 1 MB
	maxVarintBytes      = 10
	maxFieldNumber      = 1<<29 - 1 // protobuf max
)

// IsProtobufData uses heuristics to detect if data might be protobuf encoded.
// Checks for valid wire type distribution, varint continuation patterns,
// and sufficient entropy to distinguish from text protocols.
func IsProtobufData(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	limit := min(len(data), 100)

	hasVarintPattern := false
	wireTypeCount := make(map[int]int)

	for i := range limit {
		b := data[i]
		wireType := int(b & 0x07)

		if wireType <= 5 {
			wireTypeCount[wireType]++
		}

		if b&0x80 != 0 && i+1 < len(data) {
			hasVarintPattern = true
		}
	}

	totalValidBytes := 0
	for _, count := range wireTypeCount {
		totalValidBytes += count
	}

	entropy := CalculateEntropy(data)

	return hasVarintPattern && len(wireTypeCount) >= 2 && totalValidBytes > limit/4 && entropy > 3.0
}

// DecodeMessages attempts to decode one or more protobuf messages from raw bytes.
func DecodeMessages(data []byte) ([][]Field, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	var messages [][]Field
	buf := bytes.NewReader(data)

	for range maxMessagesPerParse {
		if buf.Len() == 0 {
			break
		}

		msg, err := ParseMessage(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return messages, err
		}
		if len(msg) > 0 {
			messages = append(messages, msg)
		}
	}

	if len(messages) == 0 {
		return nil, fmt.Errorf("no valid protobuf messages found")
	}

	return messages, nil
}

// ParseMessage parses a single protobuf message from a reader.
// Returns fields in wire order.
func ParseMessage(buf *bytes.Reader) ([]Field, error) {
	var fields []Field
	fieldCount := 0

	for fieldCount < maxFieldsPerMessage {
		tag, err := ReadVarint(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		fieldNumber := tag >> 3
		wireType := tag & 0x07

		if fieldNumber == 0 || fieldNumber > maxFieldNumber {
			return nil, fmt.Errorf("invalid field number: %d", fieldNumber)
		}

		fieldCount++

		switch wireType {
		case 0: // Varint
			value, vErr := ReadVarint(buf)
			if vErr != nil {
				return nil, vErr
			}
			fields = append(fields, Field{
				Number: fieldNumber,
				Type:   "varint",
				Value:  strconv.FormatUint(value, 10),
			})

		case 1: // 64-bit fixed
			var value uint64
			if fErr := readFixed64(buf, &value); fErr != nil {
				return nil, fErr
			}
			fields = append(fields, Field{
				Number: fieldNumber,
				Type:   "fixed64",
				Value:  strconv.FormatUint(value, 10),
			})

		case 2: // Length-delimited (string, bytes, nested message, packed repeated)
			length, lErr := ReadVarint(buf)
			if lErr != nil {
				return nil, lErr
			}
			if length > maxFieldSize {
				return nil, fmt.Errorf("field too large: %d bytes", length)
			}
			if length == 0 {
				fields = append(fields, Field{
					Number: fieldNumber,
					Type:   "string",
					Value:  "",
				})
				continue
			}

			value := make([]byte, length)
			n, rErr := buf.Read(value)
			if rErr != nil {
				return nil, rErr
			}
			if n != int(length) {
				return nil, fmt.Errorf("incomplete read: expected %d bytes, got %d", length, n)
			}

			if nested, nErr := tryParseNested(value); nErr == nil && len(nested) > 0 {
				fields = append(fields, Field{
					Number: fieldNumber,
					Type:   "nested",
					Value:  formatNested(nested),
				})
			} else if IsPrintable(value) {
				fields = append(fields, Field{
					Number: fieldNumber,
					Type:   "string",
					Value:  string(value),
				})
			} else {
				fields = append(fields, Field{
					Number: fieldNumber,
					Type:   "bytes",
					Value:  fmt.Sprintf("[%d bytes]", len(value)),
				})
			}

		case 3, 4: // Deprecated group start/end — skip gracefully
			continue

		case 5: // 32-bit fixed
			var value uint32
			if fErr := readFixed32(buf, &value); fErr != nil {
				return nil, fErr
			}
			fields = append(fields, Field{
				Number: fieldNumber,
				Type:   "fixed32",
				Value:  strconv.FormatUint(uint64(value), 10),
			})

		default:
			return nil, fmt.Errorf("unknown wire type: %d", wireType)
		}
	}

	return fields, nil
}

// formatNested formats a nested message's fields as a compact string.
func formatNested(fields []Field) string {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			buf.WriteString(", ")
		}
		fmt.Fprintf(&buf, "%s_%d=%s", f.Type, f.Number, f.Value)
	}
	buf.WriteByte('}')
	return buf.String()
}

// tryParseNested attempts to parse bytes as a nested protobuf message.
// Returns nil if the data doesn't look like a valid message.
func tryParseNested(data []byte) ([]Field, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("too short")
	}

	buf := bytes.NewReader(data)
	msg, err := ParseMessage(buf)
	if err != nil {
		return nil, err
	}
	if len(msg) == 0 {
		return nil, fmt.Errorf("empty nested message")
	}

	// Only accept if we consumed most of the data (avoids false positives)
	if buf.Len() > len(data)/4 {
		return nil, fmt.Errorf("too much remaining data for nested message")
	}

	return msg, nil
}

// ReadVarint reads a varint-encoded uint64 from the reader.
func ReadVarint(buf *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint

	for range maxVarintBytes {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, err
		}

		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, nil
		}

		shift += 7
		if shift >= 64 {
			return 0, fmt.Errorf("varint too long")
		}
	}

	return 0, fmt.Errorf("varint exceeds maximum length")
}

func readFixed32(buf *bytes.Reader, value *uint32) error {
	b := make([]byte, 4)
	if _, err := io.ReadFull(buf, b); err != nil {
		return err
	}
	*value = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	return nil
}

func readFixed64(buf *bytes.Reader, value *uint64) error {
	b := make([]byte, 8)
	if _, err := io.ReadFull(buf, b); err != nil {
		return err
	}
	*value = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return nil
}

// IsPrintable returns true if all bytes are printable ASCII.
func IsPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// CalculateEntropy computes Shannon entropy of the data in bits.
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// DetectMessageType classifies a decoded message based on field patterns.
func DetectMessageType(fields []Field) string {
	if len(fields) == 0 {
		return "unknown"
	}

	// Index by field number for pattern matching
	byNum := make(map[uint64]Field, len(fields))
	for _, f := range fields {
		byNum[f.Number] = f
	}

	// Check for timestamp-like varint values
	for _, f := range fields {
		if f.Type == "varint" {
			if v, err := strconv.ParseUint(f.Value, 10, 64); err == nil {
				if v > 1000000000 && v < 9999999999 {
					return "timestamped_message"
				}
			}
		}
	}

	// Check for gRPC-like method+path pattern in fields 1 and 2
	f1, has1 := byNum[1]
	f2, has2 := byNum[2]
	if has1 && has2 && f1.Type == "string" && f2.Type == "string" {
		if isHTTPMethod(f1.Value) && len(f2.Value) > 0 && f2.Value[0] == '/' {
			return "grpc_request"
		}
	}

	return "generic"
}

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// DetectServiceName guesses the service type from port numbers.
func DetectServiceName(srcPort, dstPort int32) string {
	switch {
	case srcPort == 443 || dstPort == 443:
		return "https/grpc"
	case srcPort == 80 || dstPort == 80:
		return "http"
	case srcPort == 9090 || dstPort == 9090:
		return "grpc"
	case inRange(srcPort, 8000, 8999) || inRange(dstPort, 8000, 8999):
		return "custom_service"
	case srcPort == 50051 || dstPort == 50051:
		return "grpc"
	default:
		return "unknown"
	}
}

func inRange(port, lo, hi int32) bool {
	return port >= lo && port <= hi
}

// PopulateFields converts ordered decoded fields into the audit record's
// Fields map (keyed as "type_fieldnum") and FieldOrder slice (preserving wire order).
func PopulateFields(fields []Field, out map[string]string, order *[]string) {
	for _, f := range fields {
		key := fmt.Sprintf("%s_%d", f.Type, f.Number)
		out[key] = f.Value
		*order = append(*order, key)
	}
}
