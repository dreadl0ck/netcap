# File Format Detection and Enhanced Error Messages

## Overview

NETCAP now provides enhanced error messages when attempting to open PCAP or PCAPNG files with invalid or unsupported formats. The system automatically detects file types based on their magic numbers (file signatures) and provides helpful feedback to users.

## Supported Format Detection

The system can identify the following file formats by their magic numbers:

### Packet Capture Formats

- **PCAP** (0xa1b2c3d4 / 0xd4c3b2a1) - Standard PCAP files
- **PCAP with nanosecond resolution** (0xa1b23c4d / 0x4d3cb2a1)
- **PCAPNG** (0x0a0d0d0a) - PCAP Next Generation format

### Archive Formats

- **ZIP** (0x504b0304) - ZIP archives
- **GZIP** (0x1f8b0800 / 0x1f9e0800) - GZIP compressed files
- **BZIP2** (0x425a6839) - BZIP2 compressed files

### Other Capture Formats

- **Snoop** (0x58435032) - Sun/Solaris Snoop captures
- **NetMon** (0x7663722d) - Microsoft Network Monitor captures

### Data Formats

- **JSON** (0x7b226e61) - JSON text files
- **XML** (0x3c3f786d) - XML text files

## Example Error Messages

### Known Format (ZIP)

When attempting to open a ZIP file as a PCAP:

```
Error: failed to collect audit records from pcapng file: File format error: ZIP
  File: /path/to/capture.zip
  Detected format: ZIP - ZIP archive (magic: 0x504b0304)
  Suggestion: This is a ZIP archive. Extract the PCAP/PCAPNG file first before processing.
  Original error: Unknown magic 504b0304
```

### Unknown Format

When encountering an unrecognized file format (e.g., the magic number 0x5d8cfe2e):

```
Error: failed to collect audit records from pcapng file: File format error: Unknown or unsupported format
  File: /path/to/file.pcap
  Magic number: 0x5d8cfe2e
    System 'file' command identifies this as: Non-ISO extended-ASCII text, with no line terminators
  
  This does not appear to be a valid PCAP or PCAPNG file.
  
  Possible causes:
  - File is corrupted or incomplete
  - File is in an unsupported capture format
  - File is compressed (try: gunzip, bunzip2, or unzip)
  - File is not actually a packet capture
  
  Original error: Unknown magic 5d8cfe2e
```

**Note:** NETCAP automatically invokes the system `file` command (if available) and includes its output in the error message for unknown formats!

### ASCII Hint

For magic numbers that contain printable ASCII characters (like 0x73726576 = "vers"):

```
Error: failed to collect audit records from pcapng file: File format error: Unknown or unsupported format
  File: /path/to/file.pcap
  Magic number: 0x73726576 (ASCII: 'vers')
    System 'file' command identifies this as: ASCII text, with no line terminators
  
  This does not appear to be a valid PCAP or PCAPNG file.
  ...
```

The error message shows both the ASCII interpretation AND the system `file` command output!

## Implementation Details

### Magic Number Detection

The system reads the first 4 bytes of a file and interprets them as a 32-bit integer in both little-endian and big-endian formats, checking against a database of known file format signatures.

### File Type Identification

Located in `collector/pcap_utils.go`:

- `identifyFileTypeByMagic(filePath string)` - Reads file magic number and identifies format
- `invokeFileCommand(filePath string)` - Executes system `file` command and returns output
- `enhancePcapError(filePath string, originalErr error)` - Enhances error messages with format information and `file` command output

### Integration

The enhanced error handling is automatically applied when opening PCAP/PCAPNG files through:

- `openPcapNG()` in `collector/pcapNG.go`
- `OpenPCAP()` in `collector/pcap.go`

## Troubleshooting Common Issues

### "This is a ZIP archive"

**Solution**: Extract the archive first:
```bash
unzip capture.zip
net capture -r extracted_file.pcap
```

### "This is a GZIP compressed file"

**Solution**: Decompress first:
```bash
gunzip capture.pcap.gz
net capture -r capture.pcap
```

### "File is corrupted or incomplete"

**Possible causes**:
1. Download was interrupted
2. File transfer corruption
3. Storage media error
4. Partial file write

**Solution**: Try to re-download or re-generate the capture file.

### "File is in an unsupported capture format"

**Solution**: Convert to PCAP format using tools like:
```bash
# Using editcap (from Wireshark)
editcap -F pcap input.cap output.pcap

# Using tcpdump
tcpdump -r input.cap -w output.pcap
```

## Extending Format Detection

To add support for detecting additional file formats, update the `knownMagicNumbers` map in `collector/pcap_utils.go`:

```go
var knownMagicNumbers = map[uint32]fileTypeInfo{
    0x12345678: {
        name:        "FORMAT_NAME",
        description: "Format description",
        suggestion:  "How to handle this format",
    },
    // ... other formats
}
```

## References

- [List of file signatures (Wikipedia)](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [PCAPNG Specification](https://pcapng.com/)
- [Magic Number Database](https://www.garykessler.net/library/file_sigs.html)

## See Also

- [Logging Documentation](logging.md)
- [Live Collection](live-collection.md)
- [Error Handling](../CLAUDE.md)

