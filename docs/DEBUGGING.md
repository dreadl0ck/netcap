# Debugging and Profiling NETCAP

This guide covers debugging techniques and profiling tools for NETCAP, particularly useful for diagnosing goroutine leaks, memory issues, and performance problems.

## Table of Contents

- [Enabling pprof](#enabling-pprof)
- [Analyzing Goroutines](#analyzing-goroutines)
- [Memory Profiling](#memory-profiling)
- [CPU Profiling](#cpu-profiling)
- [Common Issues](#common-issues)

## Enabling pprof

NETCAP includes built-in support for Go's pprof profiling tool via the `-pprof` flag.

### Starting the pprof Server

```bash
# Start capture with pprof server on localhost:6060
net capture -r input.pcap -pprof localhost:6060

# Multi-file processing with pprof
net capture -r file1.pcap,file2.pcap,file3.pcap -pprof localhost:6060

# Use wildcard patterns
net capture -r "*.pcap" -pprof localhost:6060
```

When enabled, you'll see output like:
```
Starting pprof HTTP server on localhost:6060
Access profiling endpoints:
  - Goroutine profile: http://localhost:6060/debug/pprof/goroutine?debug=2
  - Heap profile:      http://localhost:6060/debug/pprof/heap
  - CPU profile:       http://localhost:6060/debug/pprof/profile
  - All profiles:      http://localhost:6060/debug/pprof/
```

## Analyzing Goroutines

Goroutine leaks are a common issue in concurrent applications. Use pprof to track goroutine count and identify leaks.

### View Goroutine Count

Access the pprof web interface to see current goroutine count:

```bash
# Open in browser
open http://localhost:6060/debug/pprof/

# Or use curl
curl http://localhost:6060/debug/pprof/
```

### Detailed Goroutine Stack Traces

Get detailed stack traces for all goroutines:

```bash
# Human-readable format
curl "http://localhost:6060/debug/pprof/goroutine?debug=2" > goroutines.txt

# View in terminal
curl "http://localhost:6060/debug/pprof/goroutine?debug=2" | less
```

The output shows:
- Total number of goroutines
- Stack trace for each goroutine
- Function calls and locations

### Example: Detecting Goroutine Leaks in Multi-File Mode

When processing multiple files, monitor goroutine count between files:

```bash
# Terminal 1: Run capture
net capture -r "*.pcap" -pprof localhost:6060

# Terminal 2: Monitor goroutines
watch -n 1 'curl -s http://localhost:6060/debug/pprof/goroutine?debug=1 | grep "goroutine profile:"'
```

**Expected behavior**: Goroutine count should stabilize after the first file.  
**Leak indicator**: Goroutine count increases with each file processed.

### Interactive Analysis with go tool pprof

```bash
# Interactive mode
go tool pprof http://localhost:6060/debug/pprof/goroutine

# Once in pprof interactive mode:
(pprof) top     # Show top functions by goroutine count
(pprof) list    # Show source code
(pprof) traces  # Show stack traces
(pprof) web     # Open visualization in browser (requires graphviz)
```

## Memory Profiling

Track memory usage and identify memory leaks:

### Heap Profile

```bash
# Download heap profile
curl http://localhost:6060/debug/pprof/heap > heap.prof

# Analyze with go tool
go tool pprof heap.prof

# Or directly from URL
go tool pprof http://localhost:6060/debug/pprof/heap
```

### Common pprof Commands

```bash
# In pprof interactive mode:
(pprof) top           # Top memory consumers
(pprof) top -cum      # Cumulative allocation
(pprof) list <func>   # Show source for function
(pprof) web           # Visualization
(pprof) pdf > mem.pdf # Export to PDF
```

### Memory Stats Endpoint

```bash
# Get current memory statistics
curl http://localhost:6060/debug/pprof/heap?debug=1
```

## CPU Profiling

Identify performance bottlenecks:

### Capture CPU Profile

```bash
# 30-second CPU profile
curl "http://localhost:6060/debug/pprof/profile?seconds=30" > cpu.prof

# Analyze
go tool pprof cpu.prof
```

### Flame Graphs

Generate flame graphs for visual analysis:

```bash
# Install pprof with web UI support
go install github.com/google/pprof@latest

# Generate flame graph
pprof -http=:8080 cpu.prof
```

## Common Issues

### Issue: Goroutine Leak in Multi-File Mode

**Symptoms**: Goroutine count increases by N with each file processed.

**Diagnosis**:
```bash
# Capture goroutine profile after processing 2-3 files
curl "http://localhost:6060/debug/pprof/goroutine?debug=2" > goroutines.txt

# Look for patterns like:
grep -A 10 "created by" goroutines.txt | sort | uniq -c | sort -rn
```

**Fixed Issues**:
- ✅ Signal handler goroutines (2 per file) - Fixed by adding `signalStop` cleanup
- See git history for the complete fix

### Issue: Memory Growth

**Symptoms**: Memory usage increases continuously during processing.

**Diagnosis**:
```bash
# Compare heap profiles at different points
curl http://localhost:6060/debug/pprof/heap > heap1.prof
# ... wait and process more files ...
curl http://localhost:6060/debug/pprof/heap > heap2.prof

# Compare
go tool pprof -base heap1.prof heap2.prof
```

**Common causes**:
- Unclosed file handles
- Unbounded caches (check software.ResetCaches(), credentials.ResetCredStore(), etc.)
- TCP reassembly page caches (should be flushed via c.FlushAssemblers())

### Issue: Slow Performance

**Diagnosis**:
```bash
# 30-second CPU profile during slow operation
curl "http://localhost:6060/debug/pprof/profile?seconds=30" > cpu.prof

# Find hotspots
go tool pprof -top cpu.prof

# Trace analysis
go tool pprof -traces cpu.prof
```

## Advanced Debugging

### Block Profiling

Track goroutine blocking:

```bash
# Enable block profiling (in code, add to init or main):
# runtime.SetBlockProfileRate(1)

# Get block profile
curl http://localhost:6060/debug/pprof/block > block.prof
go tool pprof block.prof
```

### Mutex Profiling

Track mutex contention:

```bash
# Enable mutex profiling (in code):
# runtime.SetMutexProfileFraction(1)

# Get mutex profile
curl http://localhost:6060/debug/pprof/mutex > mutex.prof
go tool pprof mutex.prof
```

### All Available Endpoints

```
/debug/pprof/              # Index of all profiles
/debug/pprof/goroutine     # Goroutine stack traces
/debug/pprof/heap          # Heap memory profile
/debug/pprof/allocs        # All past memory allocations
/debug/pprof/threadcreate  # Thread creation profile
/debug/pprof/block         # Blocking profile
/debug/pprof/mutex         # Mutex contention profile
/debug/pprof/profile       # CPU profile (30s default)
/debug/pprof/trace         # Execution trace
```

## Best Practices

1. **Always enable pprof during development and testing**
   ```bash
   net capture -r test.pcap -pprof localhost:6060
   ```

2. **Monitor goroutine count in multi-file mode**
   - Should stabilize after first file
   - Increases indicate leaks

3. **Take profiles at multiple points**
   - Before processing
   - During processing
   - After each file (in multi-file mode)
   - Compare to identify trends

4. **Use version control for profiles**
   ```bash
   mkdir profiles
   curl http://localhost:6060/debug/pprof/goroutine > profiles/goroutines-$(date +%s).txt
   ```

5. **Combine with runtime stats**
   ```bash
   # Also check runtime goroutine count
   # NETCAP prints this in multi-file mode:
   # "Memory after cleanup: Heap Alloc=..., Goroutines=N"
   ```

## References

- [Go pprof Documentation](https://pkg.go.dev/net/http/pprof)
- [Go Blog: Profiling Go Programs](https://go.dev/blog/pprof)
- [Practical Go: Profiling](https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go)
- [NETCAP Multi-File Processing](WILDCARD-CAPTURE.md)
- [NETCAP State Reset Implementation](STATE-RESET-IMPLEMENTATION.md)

