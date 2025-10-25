# Enhanced File Format Error Messages - Implementation Summary

## Problem

Previously, when NETCAP encountered an invalid or unsupported file format, users would receive a cryptic error message like:

```
Error: failed to collect audit records from pcapng file: Unknown magic 5d8cfe2e
```

This provided no context about:
- What the magic number represents
- Whether the file is a known format
- What steps to take to resolve the issue
- Whether the file is corrupted or simply in the wrong format

## Solution

Implemented intelligent file format detection that:

1. **Identifies the file type** by reading the first 4 bytes (magic number)
2. **Matches against a database** of known file format signatures
3. **Provides contextual error messages** with actionable suggestions
4. **Shows ASCII interpretation** when applicable for unknown formats

## Implementation

### Files Modified

1. **collector/pcap_utils.go**
   - Added `fileTypeInfo` struct to represent file format information
   - Added `knownMagicNumbers` map with 13+ common file formats
   - Added `identifyFileTypeByMagic()` function to detect file types
   - Added `enhancePcapError()` function to enhance error messages

2. **collector/pcapNG.go**
   - Updated `openPcapNG()` to use enhanced error messages

3. **collector/pcap.go**
   - Updated `OpenPCAP()` to use enhanced error messages

4. **collector/pcap_utils_test.go** (new file)
   - Added comprehensive tests for file type identification
   - Added tests for enhanced error messages

5. **docs/FILE_FORMAT_DETECTION.md** (new file)
   - Complete documentation of the feature
   - Examples of error messages
   - Troubleshooting guide

## Examples

### Before (Unknown Format)

```
Error: failed to collect audit records from pcapng file: Unknown magic 5d8cfe2e
```

### After (Unknown Format)

```
Error: failed to collect audit records from pcapng file: File format error: Unknown or unsupported format
  File: /path/to/file.pcap
  Magic number: 0x5d8cfe2e
  This does not appear to be a valid PCAP or PCAPNG file.
  
  Possible causes:
  - File is corrupted or incomplete
  - File is in an unsupported capture format
  - File is compressed (try: gunzip, bunzip2, or unzip)
  - File is not actually a packet capture
  
  To verify the file type, try: file /path/to/file.pcap
  Original error: Unknown magic 5d8cfe2e
```

### Before (ZIP File)

```
Error: failed to collect audit records from pcapng file: Unknown magic 504b0304
```

### After (ZIP File)

```
Error: failed to collect audit records from pcapng file: File format error: ZIP
  File: /path/to/capture.zip
  Detected format: ZIP - ZIP archive (magic: 0x504b0304)
  Suggestion: This is a ZIP archive. Extract the PCAP/PCAPNG file first before processing.
  Original error: Unknown magic 504b0304
```

### Real-World Example

Testing with an invalid file:

```bash
$ echo "This is not a pcap file" > test.pcap
$ net capture -read test.pcap
```

**Output:**
```
Error: failed to collect audit records from pcapng file: File format error: Unknown or unsupported format
  File: test.pcap
  Magic number: 0x73696854 (ASCII: 'This')
  This does not appear to be a valid PCAP or PCAPNG file.
  
  Possible causes:
  - File is corrupted or incomplete
  - File is in an unsupported capture format
  - File is compressed (try: gunzip, bunzip2, or unzip)
  - File is not actually a packet capture
  
  To verify the file type, try: file test.pcap
  Original error: Unknown magic 73696854
```

Note how the system even identified that the magic number `0x73696854` corresponds to ASCII text "This".

## Supported Formats

The system can identify and provide specific guidance for:

### Packet Capture Formats
- PCAP (standard and nanosecond resolution)
- PCAPNG
- Snoop (Sun/Solaris)
- NetMon (Microsoft Network Monitor)

### Archive/Compression Formats
- ZIP
- GZIP
- BZIP2

### Data Formats
- JSON
- XML

### Unknown Formats
- Provides generic troubleshooting guidance
- Shows ASCII interpretation if applicable
- Suggests diagnostic commands

## Benefits

1. **Better User Experience**: Users immediately understand what went wrong
2. **Faster Troubleshooting**: Clear suggestions for resolution
3. **Educational**: Users learn about file formats and magic numbers
4. **Debugging Aid**: Developers can quickly identify file corruption issues
5. **Extensible**: Easy to add support for new format detection

## Testing

Comprehensive tests verify:
- Correct identification of known formats
- Appropriate error messages for unknown formats
- ASCII interpretation for text-based magic numbers
- Proper handling of corrupted/incomplete files

Run tests with:
```bash
cd collector
go test -v -run TestIdentifyFileTypeByMagic
go test -v -run TestEnhancePcapError
```

## Future Enhancements

Potential improvements:
1. Add automatic decompression for GZIP/BZIP2 files
2. Add automatic extraction for ZIP archives
3. Add support for more exotic capture formats
4. Integrate with the `file` command for unknown formats
5. Add telemetry to track most common format errors

## References

- [List of file signatures (Wikipedia)](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [PCAPNG Specification](https://pcapng.com/)
- [Magic Number Database](https://www.garykessler.net/library/file_sigs.html)

## Related Issues

This enhancement addresses the issue mentioned in `docs/TODO.md`:
```
- ICS pcaps: failed to collect audit records from pcapng file: Unknown magic 73726576
```

And resolves the user's question about magic number `5d8cfe2e`.

