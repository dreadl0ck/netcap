# Protocol Buffer Decoder for NETCAP

## Overview

The Protocol Buffer (protobuf) decoder is a new application layer decoder for NETCAP that provides general protocol buffer decoding support. This decoder can identify, parse, and extract information from protobuf-encoded data streams in network traffic.

## Features

### Detection Capabilities

The protobuf decoder uses sophisticated heuristics to identify potential protobuf data:

- **Wire Type Analysis**: Validates protobuf wire types (0-5) and their frequency
- **Varint Pattern Detection**: Identifies varint encoding patterns characteristic of protobuf
- **Entropy Analysis**: Uses Shannon entropy to distinguish binary protobuf data from text protocols
- **Structure Validation**: Ensures data follows protobuf field structure patterns

### Parsing Capabilities

Once protobuf data is detected, the decoder extracts:

- **Field Numbers and Types**: Identifies field numbers and their wire types
- **Field Values**: Extracts values for different wire types:
  - Varint (int32, int64, uint32, uint64, bool, enum)
  - Fixed64 (fixed64, sfixed64, double)
  - Length-delimited (string, bytes, embedded messages)
  - Fixed32 (fixed32, sfixed32, float)
- **Message Structure**: Reconstructs message structure from raw bytes
- **Multiple Messages**: Handles multiple protobuf messages in a single stream

### Metadata Extraction

The decoder provides additional context:

- **Service Detection**: Attempts to identify the service based on port numbers
- **Message Type Classification**: Categorizes messages (gRPC requests, timestamped messages, etc.)
- **Error Handling**: Captures parsing errors and validation failures
- **Flow Information**: Records source/destination IPs and ports

## Usage

### Stream Decoder Registration

The protobuf decoder is automatically registered as a stream decoder on port 9090 (common gRPC port) but can detect protobuf data on any port through its heuristic analysis.

### Output Format

The decoder generates `types.Protobuf` audit records with the following fields:

```go
type Protobuf struct {
    Timestamp       int64             // When the data was captured
    SrcIP           string            // Source IP address
    DstIP           string            // Destination IP address
    SrcPort         int32             // Source port
    DstPort         int32             // Destination port
    PayloadSize     int32             // Size of the protobuf payload
    PayloadEntropy  float64           // Shannon entropy of the data
    ServiceName     string            // Detected service name
    MessageType     string            // Detected message type
    Fields          map[string]string // Extracted field values
    RawPayload      []byte            // Original protobuf data
    IsValid         bool              // Whether parsing succeeded
    ErrorMsg        string            // Error message if parsing failed
    DetectionMethod string            // How protobuf was detected
    FieldTypes      []string          // Types of detected fields
    MessageCount    int32             // Number of messages in payload
}
```

### Configuration

The decoder supports standard NETCAP configuration options:

- **Output Formats**: CSV, JSON, Protocol Buffers
- **Compression**: Optional compression of output files
- **Elastic Search**: Direct export to Elastic Stack
- **Metrics**: Prometheus metrics for monitoring

## Detection Heuristics

### Primary Detection Criteria

1. **Wire Type Validation**: At least 2 different valid wire types present
2. **Varint Patterns**: Presence of varint continuation bits
3. **Entropy Threshold**: Shannon entropy > 3.0 (indicating binary data)
4. **Structure Ratio**: Valid protobuf bytes comprise >25% of data

### Service Detection

The decoder identifies services based on:

- **Port 443**: HTTPS/gRPC over TLS
- **Port 80**: HTTP (may contain protobuf over HTTP/2)
- **Port 9090**: Standard gRPC port
- **Ports 8000-8999**: Custom services (often gRPC)

### Message Type Classification

- **gRPC Request**: Messages with HTTP method and path-like fields
- **Timestamped Message**: Messages containing Unix timestamp fields
- **Generic**: Other protobuf messages

## Safety Features

### Protection Against Malformed Data

- **Field Limits**: Maximum 100 fields per message
- **Message Limits**: Maximum 10 messages per stream
- **Size Limits**: Maximum 1MB per field
- **Varint Limits**: Maximum 10 bytes per varint
- **Timeout Protection**: Built-in limits prevent infinite loops

### Error Handling

- **Graceful Degradation**: Failed parsing doesn't crash the decoder
- **Error Reporting**: Detailed error messages for troubleshooting
- **Partial Results**: Valid fields extracted even if message parsing fails

## Performance Considerations

### Optimizations

- **Early Exit**: Quick rejection of non-protobuf data
- **Streaming Processing**: Processes data as it arrives
- **Memory Efficient**: Minimal memory allocation for large streams
- **Concurrent Safe**: Thread-safe for parallel processing

### Benchmarks

Based on test results:

- **Detection**: ~0.009s for typical protobuf validation
- **Parsing**: Handles complex messages with multiple fields efficiently
- **Memory**: Low allocation overhead with safety limits

## Examples

### Valid Protobuf Detection

```go
// Sample protobuf data with multiple fields
data := []byte{
    0x08, 0x96, 0x01,               // field 1, varint, value 150
    0x12, 0x04, 0x74, 0x65, 0x73, 0x74, // field 2, string, "test"
    0x18, 0x00,                     // field 3, varint, value 0
}

// This would be detected as valid protobuf and parsed
```

### Output Example

```json
{
    "Timestamp": 1640995200000000000,
    "SrcIP": "192.168.1.100",
    "DstIP": "192.168.1.200",
    "SrcPort": 45123,
    "DstPort": 9090,
    "PayloadSize": 11,
    "PayloadEntropy": 4.32,
    "ServiceName": "grpc",
    "MessageType": "generic",
    "Fields": {
        "field_1": "150",
        "field_2": "test",
        "field_3": "0"
    },
    "IsValid": true,
    "DetectionMethod": "heuristic",
    "FieldTypes": ["uint64", "string", "uint64"],
    "MessageCount": 1
}
```

## Integration

### With Existing NETCAP Decoders

The protobuf decoder works alongside existing decoders:

- **HTTP Decoder**: May capture protobuf over HTTP/2
- **TLS Decoder**: Combined with TLS for encrypted protobuf
- **TCP Decoder**: Provides transport layer context

### With Analysis Tools

- **Elastic Stack**: Direct integration for search and visualization
- **Prometheus**: Metrics for monitoring protobuf traffic
- **Custom Analysis**: CSV/JSON output for custom tools

## Limitations

### Current Limitations

1. **Schema-less**: Decodes structure but not semantic meaning
2. **No Type Inference**: Cannot determine exact protobuf message types
3. **Limited gRPC Support**: Basic detection, not full gRPC protocol parsing
4. **Binary Data**: Only handles wire format, not JSON/text protobuf

### Future Enhancements

- **Schema Integration**: Support for .proto files to add semantic meaning
- **gRPC Protocol Support**: Full gRPC method and status code extraction
- **Performance Optimizations**: Further speed improvements for high-volume traffic
- **Advanced Heuristics**: Better detection accuracy for edge cases

## Testing

The decoder includes comprehensive tests covering:

- **Detection Accuracy**: Various data types and edge cases
- **Parsing Robustness**: Malformed and edge case protobuf data
- **Performance**: Benchmarks for detection and parsing speed
- **Safety**: Protection against infinite loops and crashes

Run tests with:
```bash
cd decoder/stream/protobuf
go test -v
```

## Contributing

When contributing to the protobuf decoder:

1. **Add Tests**: Include tests for new features or bug fixes
2. **Safety First**: Ensure all loops have limits and error handling
3. **Performance**: Consider impact on high-volume traffic scenarios
4. **Documentation**: Update this documentation for new features

## Support

For issues or questions related to the protobuf decoder:

1. Check existing NETCAP documentation
2. Review test cases for usage examples
3. Submit issues with sample data and expected behavior
4. Provide network captures for debugging complex cases