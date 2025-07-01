/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var protobufLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_Protobuf,
	Name:        "Protobuf",
	Description: "General Protocol Buffer decoder for application layer data",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		protobufLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"protobuf",
			decoderconfig.Instance.Debug,
		)
		return err
	},
	CanDecode: func(client, server []byte) bool {
		return isProtobufData(client) || isProtobufData(server)
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return protobufLog.Sync()
	},
	Factory: &protobufReader{},
	Typ:     core.All,
}

// protobufReader implements the core.StreamDecoderInterface for protobuf data
type protobufReader struct {
	conversation *core.ConversationInfo
	
	// Stream data
	client bytes.Buffer
	server bytes.Buffer
	
	// Mutex for concurrent access
	mu sync.Mutex
}

// New creates a new protobuf reader instance
func (r *protobufReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &protobufReader{
		conversation: conversation,
	}
}

// Decode processes the conversation data and extracts protobuf messages
func (r *protobufReader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Use the stream utils to decode the conversation
	streamutils.DecodeConversation(
		r.conversation.Ident,
		r.conversation.Data,
		func(b *bufio.Reader) error {
			return r.readClient(b)
		},
		func(b *bufio.Reader) error {
			return r.readServer(b)
		},
	)
}

// readClient processes client data from the stream
func (r *protobufReader) readClient(b *bufio.Reader) error {
	data, err := b.ReadBytes('\n')
	if err != nil && err != io.EOF {
		// For protobuf, we might not have clear delimiters, so read all available data
		remaining, readErr := io.ReadAll(b)
		if readErr != nil {
			return readErr
		}
		data = append(data, remaining...)
	}

	if len(data) > 0 {
		err := r.parseProtobufData(
			data,
			r.conversation.FirstClientPacket.UnixNano(),
			true,
			r.conversation.ClientIP,
			r.conversation.ServerIP,
			r.conversation.ClientPort,
			r.conversation.ServerPort,
		)
		if err != nil {
			protobufLog.Debug("failed to parse client protobuf data", zap.Error(err))
		}
	}

	return err
}

// readServer processes server data from the stream
func (r *protobufReader) readServer(b *bufio.Reader) error {
	data, err := b.ReadBytes('\n')
	if err != nil && err != io.EOF {
		// For protobuf, we might not have clear delimiters, so read all available data
		remaining, readErr := io.ReadAll(b)
		if readErr != nil {
			return readErr
		}
		data = append(data, remaining...)
	}

	if len(data) > 0 {
		err := r.parseProtobufData(
			data,
			r.conversation.FirstServerPacket.UnixNano(),
			false,
			r.conversation.ClientIP,
			r.conversation.ServerIP,
			r.conversation.ClientPort,
			r.conversation.ServerPort,
		)
		if err != nil {
			protobufLog.Debug("failed to parse server protobuf data", zap.Error(err))
		}
	}

	return err
}

// parseProtobufData attempts to parse protobuf data from the given bytes
func (r *protobufReader) parseProtobufData(data []byte, timestamp int64, isClient bool, srcIP, dstIP string, srcPort, dstPort int32) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}

	// Create protobuf audit record
	pb := &types.Protobuf{
		Timestamp:       timestamp,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		SrcPort:         srcPort,
		DstPort:         dstPort,
		PayloadSize:     int32(len(data)),
		PayloadEntropy:  calculateEntropy(data),
		RawPayload:      data,
		Fields:          make(map[string]string),
		FieldTypes:      []string{},
		DetectionMethod: "heuristic",
	}

	// Attempt to decode protobuf messages
	messages, err := decodeProtobufMessages(data)
	if err != nil {
		pb.IsValid = false
		pb.ErrorMsg = err.Error()
		pb.MessageCount = 0
	} else {
		pb.IsValid = true
		pb.MessageCount = int32(len(messages))
		
		// Extract fields from decoded messages
		for i, msg := range messages {
			if i == 0 {
				// Use first message to determine type
				pb.MessageType = detectMessageType(msg)
				pb.ServiceName = detectServiceName(data, srcPort, dstPort)
			}
			extractFields(msg, pb.Fields, &pb.FieldTypes)
		}
	}

	// Write audit record
	return Decoder.Writer.Write(pb)
}

// isProtobufData uses heuristics to detect if data might be protobuf encoded
func isProtobufData(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// Check for common protobuf patterns
	// Protobuf uses varint encoding, so first byte often has specific patterns
	hasVarintPattern := false
	wireTypeCount := make(map[int]int)
	
	for i := 0; i < len(data) && i < 100; i++ { // Check first 100 bytes
		b := data[i]
		wireType := int(b & 0x07) // Last 3 bits indicate wire type
		
		// Valid wire types in protobuf: 0, 1, 2, 3, 4, 5
		if wireType <= 5 {
			wireTypeCount[wireType]++
		}
		
		// Look for varint patterns (MSB = 1 means continuation)
		if b&0x80 != 0 && i+1 < len(data) {
			hasVarintPattern = true
		}
	}
	
	// Heuristic: if we see valid wire types and varint patterns, likely protobuf
	validWireTypes := len(wireTypeCount)
	totalValidBytes := 0
	for _, count := range wireTypeCount {
		totalValidBytes += count
	}
	
	entropy := calculateEntropy(data)
	
	// Higher entropy suggests binary data, valid wire types suggest protobuf structure
	return hasVarintPattern && validWireTypes >= 2 && totalValidBytes > len(data)/4 && entropy > 3.0
}

// decodeProtobufMessages attempts to decode protobuf messages from raw bytes
func decodeProtobufMessages(data []byte) ([]map[string]interface{}, error) {
	var messages []map[string]interface{}
	
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	
	// Simple protobuf parser for extracting basic field information
	buf := bytes.NewReader(data)
	maxMessages := 10 // Safety limit
	messageCount := 0
	
	for messageCount < maxMessages {
		if buf.Len() == 0 {
			break
		}
		
		msg, err := parseProtobufMessage(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(msg) > 0 {
			messages = append(messages, msg)
		}
		messageCount++
	}
	
	if len(messages) == 0 {
		return nil, fmt.Errorf("no valid protobuf messages found")
	}
	
	return messages, nil
}

// parseProtobufMessage parses a single protobuf message
func parseProtobufMessage(buf *bytes.Reader) (map[string]interface{}, error) {
	message := make(map[string]interface{})
	maxFields := 100 // Safety limit to prevent infinite loops
	fieldCount := 0
	
	for fieldCount < maxFields {
		// Read field tag (varint encoding)
		tag, err := readVarint(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		
		fieldNumber := tag >> 3
		wireType := tag & 0x07
		
		// Safety check for field number
		if fieldNumber == 0 || fieldNumber > 536870911 { // Max field number in protobuf is 2^29 - 1
			return nil, fmt.Errorf("invalid field number: %d", fieldNumber)
		}
		
		fieldName := fmt.Sprintf("field_%d", fieldNumber)
		fieldCount++
		
		switch wireType {
		case 0: // Varint
			value, err := readVarint(buf)
			if err != nil {
				return nil, err
			}
			message[fieldName] = value
			
		case 1: // 64-bit
			var value uint64
			err := readFixed64(buf, &value)
			if err != nil {
				return nil, err
			}
			message[fieldName] = value
			
		case 2: // Length-delimited
			length, err := readVarint(buf)
			if err != nil {
				return nil, err
			}
			
			if length > 1024*1024 { // Sanity check: max 1MB per field
				return nil, fmt.Errorf("field too large: %d bytes", length)
			}
			
			if length == 0 {
				message[fieldName] = ""
				continue
			}
			
			value := make([]byte, length)
			n, err := buf.Read(value)
			if err != nil {
				return nil, err
			}
			if n != int(length) {
				return nil, fmt.Errorf("incomplete read: expected %d bytes, got %d", length, n)
			}
			
			// Try to decode as string if printable
			if isPrintable(value) {
				message[fieldName] = string(value)
			} else {
				message[fieldName] = fmt.Sprintf("bytes[%d]", len(value))
			}
			
		case 5: // 32-bit
			var value uint32
			err := readFixed32(buf, &value)
			if err != nil {
				return nil, err
			}
			message[fieldName] = value
			
		default:
			return nil, fmt.Errorf("unknown wire type: %d", wireType)
		}
	}
	
	if fieldCount >= maxFields {
		return nil, fmt.Errorf("too many fields in message (limit: %d)", maxFields)
	}
	
	return message, nil
}

// Helper functions for protobuf parsing

func readVarint(buf *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint
	maxBytes := 10 // Max bytes for a 64-bit varint
	bytesRead := 0
	
	for bytesRead < maxBytes {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, err
		}
		
		bytesRead++
		result |= uint64(b&0x7F) << shift
		
		if b&0x80 == 0 {
			break
		}
		
		shift += 7
		if shift >= 64 {
			return 0, fmt.Errorf("varint too long")
		}
	}
	
	if bytesRead >= maxBytes {
		return 0, fmt.Errorf("varint exceeds maximum length")
	}
	
	return result, nil
}

func readFixed32(buf *bytes.Reader, value *uint32) error {
	bytes := make([]byte, 4)
	_, err := buf.Read(bytes)
	if err != nil {
		return err
	}
	
	*value = uint32(bytes[0]) | uint32(bytes[1])<<8 | uint32(bytes[2])<<16 | uint32(bytes[3])<<24
	return nil
}

func readFixed64(buf *bytes.Reader, value *uint64) error {
	bytes := make([]byte, 8)
	_, err := buf.Read(bytes)
	if err != nil {
		return err
	}
	
	*value = uint64(bytes[0]) | uint64(bytes[1])<<8 | uint64(bytes[2])<<16 | uint64(bytes[3])<<24 |
		uint64(bytes[4])<<32 | uint64(bytes[5])<<40 | uint64(bytes[6])<<48 | uint64(bytes[7])<<56
	return nil
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// calculateEntropy calculates Shannon entropy of the data
func calculateEntropy(data []byte) float64 {
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

// detectMessageType attempts to identify the message type based on field patterns
func detectMessageType(message map[string]interface{}) string {
	// Simple heuristics based on common protobuf patterns
	if len(message) == 0 {
		return "unknown"
	}
	
	// Look for timestamp fields first (common in many protobuf messages)
	for _, value := range message {
		if val, ok := value.(uint64); ok {
			// Check if it could be a timestamp (reasonable range)
			if val > 1000000000 && val < 9999999999 { // Rough Unix timestamp range
				return "timestamped_message"
			}
		}
	}
	
	// Look for common gRPC/HTTP2 patterns (check for string values)
	if field1, hasField1 := message["field_1"]; hasField1 {
		if field2, hasField2 := message["field_2"]; hasField2 {
			// Check if both are strings that look like HTTP method and path
			if str1, ok1 := field1.(string); ok1 {
				if str2, ok2 := field2.(string); ok2 {
					if (str1 == "GET" || str1 == "POST" || str1 == "PUT" || str1 == "DELETE") && 
					   len(str2) > 0 && (str2[0] == '/' || (len(str2) >= 4 && str2[0:4] == "http")) {
						return "grpc_request"
					}
				}
			}
		}
	}
	
	return "generic"
}

// detectServiceName attempts to identify the service based on port and data patterns
func detectServiceName(data []byte, srcPort, dstPort int32) string {
	// Common gRPC/HTTP2 ports
	switch {
	case srcPort == 443 || dstPort == 443:
		return "https/grpc"
	case srcPort == 80 || dstPort == 80:
		return "http"
	case srcPort == 9090 || dstPort == 9090:
		return "grpc"
	case srcPort >= 8000 && srcPort < 9000:
		return "custom_service"
	case dstPort >= 8000 && dstPort < 9000:
		return "custom_service"
	default:
		return "unknown"
	}
}

// extractFields extracts field information from a decoded message
func extractFields(message map[string]interface{}, fields map[string]string, fieldTypes *[]string) {
	for key, value := range message {
		switch v := value.(type) {
		case string:
			fields[key] = v
			*fieldTypes = append(*fieldTypes, "string")
		case uint64:
			fields[key] = strconv.FormatUint(v, 10)
			*fieldTypes = append(*fieldTypes, "uint64")
		case uint32:
			fields[key] = strconv.FormatUint(uint64(v), 10)
			*fieldTypes = append(*fieldTypes, "uint32")
		case int64:
			fields[key] = strconv.FormatInt(v, 10)
			*fieldTypes = append(*fieldTypes, "int64")
		case int32:
			fields[key] = strconv.FormatInt(int64(v), 10)
			*fieldTypes = append(*fieldTypes, "int32")
		default:
			fields[key] = fmt.Sprintf("%v", v)
			*fieldTypes = append(*fieldTypes, "unknown")
		}
	}
}