#!/bin/bash
#
# Script to test memory usage during multi-file PCAP processing
# Monitors RSS memory and displays statistics
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NETCAP_BIN="${1:-./bin/net}"
PCAP_DIR="${2:-tests/pcaps}"
SAMPLE_SIZE="${3:-10}" # Process first N files for testing
MONITOR_INTERVAL=2     # Seconds between memory checks

echo -e "${GREEN}=== Netcap Memory Usage Test ===${NC}"
echo "Binary: $NETCAP_BIN"
echo "PCAP Directory: $PCAP_DIR"
echo "Sample Size: $SAMPLE_SIZE files"
echo "Monitor Interval: ${MONITOR_INTERVAL}s"
echo ""

# Check if binary exists
if [ ! -f "$NETCAP_BIN" ]; then
    echo -e "${RED}Error: Binary not found at $NETCAP_BIN${NC}"
    echo "Build it first: cd /Users/pmieden/go/src/github.com/dreadl0ck/netcap && go build -o bin/net ./cmd/main.go"
    exit 1
fi

# Check if PCAP directory exists
if [ ! -d "$PCAP_DIR" ]; then
    echo -e "${RED}Error: PCAP directory not found at $PCAP_DIR${NC}"
    exit 1
fi

# Count available PCAP files
PCAP_COUNT=$(find "$PCAP_DIR" -name "*.pcap" -o -name "*.pcapng" | wc -l | tr -d ' ')
echo "Found $PCAP_COUNT PCAP files in $PCAP_DIR"
echo ""

if [ "$PCAP_COUNT" -eq 0 ]; then
    echo -e "${RED}Error: No PCAP files found${NC}"
    exit 1
fi

# Create temp file for memory stats
MEMORY_LOG=$(mktemp /tmp/netcap-memory-XXXXXX.log)
trap "rm -f $MEMORY_LOG" EXIT

echo -e "${YELLOW}Starting processing (logging memory to $MEMORY_LOG)...${NC}"
echo ""

# Start memory monitor in background
(
    echo "timestamp,rss_mb,vsz_mb,cpu_pct" > "$MEMORY_LOG"
    while true; do
        # Find the netcap process
        STATS=$(ps aux | grep "[n]et capture" | awk '{print $3 "," $5/1024 "," $6/1024}')
        if [ -n "$STATS" ]; then
            TIMESTAMP=$(date +%s)
            echo "$TIMESTAMP,$STATS" >> "$MEMORY_LOG"
        fi
        sleep $MONITOR_INTERVAL
    done
) &
MONITOR_PID=$!
trap "kill $MONITOR_PID 2>/dev/null; rm -f $MEMORY_LOG" EXIT

# Run netcap on sample of files
SAMPLE_FILES=$(find "$PCAP_DIR" -name "*.pcap" -o -name "*.pcapng" | head -n "$SAMPLE_SIZE")
FILE_COUNT=$(echo "$SAMPLE_FILES" | wc -l | tr -d ' ')

echo -e "${GREEN}Processing $FILE_COUNT files...${NC}"
START_TIME=$(date +%s)

# Run netcap
if $NETCAP_BIN capture -dpi -y -read $SAMPLE_FILES 2>&1 | tee netcap-output.log; then
    STATUS="SUCCESS"
    COLOR=$GREEN
else
    STATUS="FAILED"
    COLOR=$RED
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Stop memory monitor
kill $MONITOR_PID 2>/dev/null || true

echo ""
echo -e "${COLOR}=== Processing $STATUS ===${NC}"
echo "Duration: ${DURATION}s"
echo ""

# Analyze memory usage
if [ -s "$MEMORY_LOG" ] && [ $(wc -l < "$MEMORY_LOG") -gt 1 ]; then
    echo -e "${GREEN}=== Memory Statistics ===${NC}"
    
    # Skip header and calculate stats
    tail -n +2 "$MEMORY_LOG" | awk -F',' '
    BEGIN {
        min_rss = 999999
        max_rss = 0
        sum_rss = 0
        count = 0
        max_cpu = 0
    }
    {
        rss = $2
        cpu = $3
        
        if (rss < min_rss) min_rss = rss
        if (rss > max_rss) max_rss = rss
        if (cpu > max_cpu) max_cpu = cpu
        sum_rss += rss
        count++
    }
    END {
        if (count > 0) {
            avg_rss = sum_rss / count
            printf "  Min RSS Memory:  %8.2f MB\n", min_rss
            printf "  Max RSS Memory:  %8.2f MB\n", max_rss
            printf "  Avg RSS Memory:  %8.2f MB\n", avg_rss
            printf "  Peak CPU:        %8.2f %%\n", max_cpu
            printf "  Samples:         %8d\n", count
            
            # Check if memory grew significantly
            growth = max_rss - min_rss
            printf "\n"
            if (growth > min_rss * 0.5) {
                printf "  ⚠️  Memory grew by %.2f MB (%.1f%%) - potential leak\n", growth, (growth/min_rss)*100
            } else {
                printf "  ✅ Memory growth: %.2f MB (%.1f%%) - looks good\n", growth, (growth/min_rss)*100
            }
        }
    }'
    
    echo ""
    echo "Full memory log: $MEMORY_LOG"
else
    echo -e "${YELLOW}No memory statistics collected${NC}"
fi

# Check for memory cleanup reports in output
echo ""
echo -e "${GREEN}=== Memory Cleanup Reports ===${NC}"
if grep -q "Memory before cleanup" netcap-output.log 2>/dev/null; then
    grep -A1 "Memory before cleanup\|Memory after cleanup" netcap-output.log | tail -20
else
    echo "No memory cleanup reports found (normal for single file)"
fi

# Cleanup
rm -f netcap-output.log

echo ""
echo -e "${GREEN}=== Test Complete ===${NC}"
echo "To test with all files, run:"
echo "  $0 $NETCAP_BIN $PCAP_DIR 2309"

