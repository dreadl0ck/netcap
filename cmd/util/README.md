# NETCAP Utility Tools

This directory contains utility tools for NETCAP development and analysis.

## GoPacket Coverage Analysis

Analyzes all layer types provided by gopacket and checks which ones are not implemented in NETCAP. This functionality is integrated into the `net util` subcommand.

### Features

- **Fetches Layer Types**: Retrieves the latest layer type definitions from gopacket's GitHub repository
- **Scans NETCAP Decoders**: Analyzes all decoder files in `decoder/packet/` to find which layer types are used
- **Comprehensive Reporting**: Provides statistics, categorization, and recommendations
- **Coverage Analysis**: Shows the percentage of gopacket layer types supported by NETCAP

### Usage

```bash
# Analyze gopacket coverage (shows only unused layer types)
net util -gopacket-coverage

# Or if running from source
go run cmd/main.go util -gopacket-coverage
```

### Output

The command generates a text-based report with the following sections:

1. **Statistics**: Total layer types, coverage percentage, and counts
2. **Used Layer Types**: List of all gopacket layer types currently implemented in NETCAP
3. **Unused Layer Types**: Categorized list of layer types not yet implemented
   - Network Layer
   - Tunneling/Encapsulation
   - Security/Encryption
   - Wireless
   - Network Discovery
   - Monitoring/Mirroring
   - Other
4. **Recommendations**: Priority protocols that should be considered for implementation

### Example Output

```
Analyzing gopacket layer type coverage...

=== Coverage Statistics ===
Total gopacket layer types: 145
Layer types used in NETCAP: 51 (35.2%)
Layer types NOT used in NETCAP: 94 (64.8%)

=== Unused Layer Types ===

Security/Encryption (1):
  ✗ LayerTypeTLS

Tunneling/Encapsulation (4):
  ✗ LayerTypeGTPv1U
  ✗ LayerTypeGTPv2
  ✗ LayerTypePPP
  ✗ LayerTypePPPoE
...

=== High-Priority Recommendations ===
Consider implementing decoders for these commonly used protocols:
  • LayerTypeERSPANII
  • LayerTypePPP
  • LayerTypePPPoE
  • LayerTypeRadioTap
  • LayerTypeSTP
  • LayerTypeTLS
```

### How It Works

1. **Layer Type Fetching**: The tool fetches `layertypes.go` from the gopacket GitHub repository and parses it using Go's `ast` package to extract all `LayerType*` variable declarations.

2. **Decoder Scanning**: It walks through all `.go` files in the `decoder/packet/` directory and uses regex patterns to find references to `layers.LayerType*`.

3. **Analysis & Reporting**: The tool compares the two lists, categorizes unused layer types, and generates a report focused on protocols that need implementation.

### Use Cases

- **Feature Planning**: Quickly identify missing protocol decoders for future development
- **Coverage Tracking**: Monitor NETCAP's protocol support coverage over time
- **Priority Assessment**: See which commonly-used protocols should be implemented next
- **Quick Check**: Fast way to check protocol coverage during development

### Adding New Decoders

When the report shows missing layer types you want to implement:

1. Create a new decoder file in `decoder/packet/` (e.g., `tls.go` for TLS)
2. Implement the decoder using the `newGoPacketDecoder()` function
3. Reference the appropriate `layers.LayerType*` constant
4. Run `net util -gopacket-coverage` again to verify the layer type is now marked as used

### Implementation Details

The functionality is implemented in `gopacket_coverage.go` as part of the `util` package. Key functions:

- `analyzeGoPacketCoverage()`: Main entry point, orchestrates the analysis
- `fetchGoPacketLayerTypes()`: Downloads and parses gopacket's layertypes.go
- `scanNetcapDecoders()`: Scans decoder files for layer type usage
- `categorizeLayer()`: Groups layer types by protocol category

### Requirements

- Internet connection (to fetch gopacket layer types from GitHub)
- NETCAP must be built with `zeus install` or similar
- Run from within the NETCAP project directory

### Related Files

- `cmd/util/gopacket_coverage.go`: Coverage analysis implementation
- `decoder/packet/gopacket_decoder.go`: Core decoder registration logic
- `decoder/packet/*.go`: Individual protocol decoder implementations
- `types/netcap.pb.go`: Protocol buffer definitions for audit records
- `docs/LAYER_COVERAGE_ANALYSIS.md`: Detailed analysis document

## decoders.go

Contains decoder information and utilities for the `net` command-line tool.

### Features

- Lists all available decoders
- Provides decoder descriptions and layer classifications
- Groups decoders by OSI layer (Link, Network, Transport, Application)
