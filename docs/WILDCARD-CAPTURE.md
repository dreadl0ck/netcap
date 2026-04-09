# Wildcard Support for Batch PCAP Processing

## Overview

The `net capture` command now supports wildcard patterns to process multiple PCAP/PCAPNG files in batch mode. Each file is processed independently with its own output directory, and the internal state is fully reset between files.

## Usage

### Wildcard Methods

There are two ways to use wildcards with `net capture`:

#### Method 1: Shell Expansion (Recommended)
Let your shell expand the wildcard before passing files to the program:
```bash
# Shell expands *.pcap to all matching files
net capture -read *.pcap -out /output/directory

# Works with any shell glob pattern
net capture -read traffic_*.pcap -out /output/directory
```

#### Method 2: Quoted Wildcards
Use quotes to prevent shell expansion and let the program handle the wildcard:
```bash
# Program handles the wildcard expansion
net capture -read "*.pcap" -out /output/directory
net capture -read "/path/to/captures/*.pcap" -out /output/directory
```

Both methods work identically - use whichever you prefer. Shell expansion (Method 1) is more portable across different systems.

### Basic Patterns

Process all PCAP files in a directory:
```bash
net capture -read *.pcap -out /output/directory
# OR
net capture -read "*.pcap" -out /output/directory
```

Process all PCAPNG files:
```bash
net capture -read *.pcapng -out /output/directory
```

Process files with specific prefix:
```bash
net capture -read "traffic_*.pcap" -out /output/directory
```

### Directory Structure

When processing multiple files, each file gets its own subdirectory:

```
/output/directory/
├── capture1/
│   ├── TCP.ncap.gz
│   ├── UDP.ncap.gz
│   ├── HTTP.ncap.gz
│   └── ...
├── capture2/
│   ├── TCP.ncap.gz
│   ├── UDP.ncap.gz
│   ├── HTTP.ncap.gz
│   └── ...
└── capture3/
    ├── TCP.ncap.gz
    ├── UDP.ncap.gz
    ├── HTTP.ncap.gz
    └── ...
```

The subdirectory name is derived from the input filename (without the extension).

### Examples

Process all PCAP files in current directory:
```bash
net capture -read *.pcap -out ./results
```

Process PCAP files with a specific prefix:
```bash
net capture -read traffic_*.pcap -out ./results
```

Process PCAPNG files in a subdirectory:
```bash
net capture -read ./captures/*.pcapng -out ./results
```

Combine with other flags:
```bash
# Process all files with DPI enabled
net capture -read *.pcap -out ./results -dpi

# Process with BPF filter
net capture -read *.pcap -out ./results -bpf "tcp port 80"
```

## State Management

### Automatic State Reset

When processing multiple files, the following state is automatically reset between each file:

1. **Device Profiles**: All MAC address to device mappings are cleared
2. **IP Profiles**: All IP address behavior profiles are reset
3. **Connection Tables**: All network connection tracking is cleared
4. **Collector Instance**: A fresh collector is created for each file

This ensures that data from one capture file does not leak into the analysis of another file.

### Output Isolation

Each capture file's output is stored in a separate directory to prevent:
- Data mixing between different captures
- Filename conflicts
- Confusion about which audit records came from which source file

## Advanced Options

All standard `net capture` flags work with wildcard patterns:

```bash
# Process with specific decoders only
net capture -read "*.pcap" -out ./results -include "TCP,UDP,HTTP"

# Enable DPI for all files
net capture -read "*.pcap" -out ./results -dpi

# Use BPF filter on all files
net capture -read "*.pcap" -out ./results -bpf "tcp port 80"

# Quiet mode for batch processing
net capture -read "*.pcap" -out ./results -quiet

# Enable compression
net capture -read "*.pcap" -out ./results -compress
```

## Notes

- **HTTP Shutdown Endpoint**: Disabled automatically when processing multiple files to avoid port conflicts
- **Memory Management**: Each file is processed sequentially, so memory usage is limited to one file at a time
- **Error Handling**: If one file fails, the error is logged and processing continues with remaining files. A summary of all errors is displayed at the end.
- **Glob Pattern Support**: Supports standard shell glob patterns (`*`, `?`, `[...]`)
- **File Type Filtering**: Only `.pcap` and `.pcapng` **files** are processed; directories and other file types are automatically filtered out
- **Directory Exclusion**: Directories are automatically skipped even if they match the pattern
- **Shell vs Program Expansion**: Both shell-expanded and program-expanded wildcards work identically
- **No Argument Restrictions**: The previous "two consecutive args" error has been removed to support shell-expanded wildcards

## Performance Considerations

- Files are processed **sequentially**, not in parallel
- Each file gets a fresh collector instance, which includes:
  - Initialization of all decoders
  - Loading of resolver databases (cached between files)
  - Creation of output directory structure
  
For maximum performance when processing many files:
- Use `-quiet` flag to reduce output overhead
- Consider using `-workers` to tune parallelism per file
- Use `-compress=false` if disk I/O is a bottleneck
- Use `-buf=false` if memory is constrained

## Error Summary

When processing multiple files in wildcard mode, errors for individual files do not stop the entire batch. Instead, each error is logged, the problematic file is skipped, and processing continues with the next file. At the end of the batch run, a comprehensive summary is displayed:

```
========================================
Batch Processing Summary
========================================
Total files: 10
Successful: 8
Failed: 2

Errors encountered:
1. /path/to/corrupted.pcap
   Error: failed to collect audit records from pcap file: unhandled link type: LinkTypeTokenRing (raw value: 6, hex: 0x6)
2. /path/to/invalid.pcap
   Error: failed to open file: invalid pcap header
========================================
```

This allows you to:
- Process all valid files in a batch without interruption
- Identify which specific files had issues
- See the exact error for each problematic file
- Re-run or investigate failed files later

## Troubleshooting

### No files found
```
Error: no pcap or pcapng files found matching pattern: *.pcap
```
**Solution**: Check that files exist and the pattern is correct. Use absolute paths or ensure you're in the correct directory.

### Directory matched instead of file
Directories that match the pattern are automatically skipped. For example, if you have a directory named `capture.pcap`, it will be ignored and only actual `.pcap` files will be processed.

### Permission denied
**Solution**: Ensure you have read permissions on the input files and write permissions on the output directory.

### Out of memory
**Solution**: Process fewer files at once, or use memory-efficient options like `-compress=false` and `-buf=false`.

