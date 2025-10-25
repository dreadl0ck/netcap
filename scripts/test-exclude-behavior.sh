#!/bin/bash
#
# Test script to verify -exclude flag behavior
# Tests that excluding transport layer decoders (Ethernet, IPv4, TCP)
# does not prevent application layer decoders from working
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Testing -exclude flag behavior"
echo "=========================================="
echo

# Check if net binary exists
if [ ! -f "bin/net" ]; then
    echo -e "${RED}Error: bin/net not found. Please build the project first with 'go build -o bin/net cmd/main.go'${NC}"
    exit 1
fi

# Check if test PCAP exists
PCAP_FILE="data/The-Ultimate-PCAP-v20200224.pcapng"
if [ ! -f "$PCAP_FILE" ]; then
    echo -e "${YELLOW}Warning: Test PCAP not found at $PCAP_FILE${NC}"
    echo "Please provide a PCAP file with HTTP/TLS traffic for testing"
    echo
    echo "Usage: $0 [pcap_file]"
    if [ -n "$1" ]; then
        PCAP_FILE="$1"
        if [ ! -f "$PCAP_FILE" ]; then
            echo -e "${RED}Error: Provided file $PCAP_FILE does not exist${NC}"
            exit 1
        fi
    else
        exit 1
    fi
fi

echo "Using PCAP file: $PCAP_FILE"
echo

# Create temporary output directories
TEST_DIR="/tmp/netcap-exclude-test-$$"
mkdir -p "$TEST_DIR"

cleanup() {
    echo
    echo "Cleaning up test directory: $TEST_DIR"
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test 1: Normal capture (baseline)
echo -e "${YELLOW}Test 1: Baseline capture with all decoders${NC}"
TEST1_DIR="$TEST_DIR/test1-baseline"
mkdir -p "$TEST1_DIR"

./bin/net capture -read "$PCAP_FILE" -out "$TEST1_DIR" 2>&1 | tail -5

echo "Files created in baseline test:"
ls -lh "$TEST1_DIR" | grep -E '\.ncap(\.gz)?$' || true
BASELINE_FILES=$(ls "$TEST1_DIR"/*.ncap* 2>/dev/null | wc -l)
echo "Total audit record files: $BASELINE_FILES"
echo

# Test 2: Exclude transport layers
echo -e "${YELLOW}Test 2: Exclude Ethernet, IPv4, IPv6, TCP, UDP${NC}"
TEST2_DIR="$TEST_DIR/test2-exclude-transport"
mkdir -p "$TEST2_DIR"

./bin/net capture -read "$PCAP_FILE" -out "$TEST2_DIR" -exclude Ethernet,IPv4,IPv6,TCP,UDP 2>&1 | tail -5

echo "Files created with transport layers excluded:"
ls -lh "$TEST2_DIR" | grep -E '\.ncap(\.gz)?$' || true
EXCLUDED_FILES=$(ls "$TEST2_DIR"/*.ncap* 2>/dev/null | wc -l)
echo "Total audit record files: $EXCLUDED_FILES"
echo

# Verification
echo -e "${YELLOW}Verification:${NC}"
echo

# Check that excluded files are NOT present
FAILED=0
for LAYER in Ethernet IPv4 IPv6 TCP UDP; do
    if ls "$TEST2_DIR"/${LAYER}.ncap* 2>/dev/null; then
        echo -e "${RED}✗ FAIL: $LAYER audit records should NOT exist${NC}"
        FAILED=1
    else
        echo -e "${GREEN}✓ PASS: $LAYER audit records correctly excluded${NC}"
    fi
done
echo

# Check that application layer files ARE present (if they were in baseline)
if [ -f "$TEST1_DIR"/HTTP.ncap* ] 2>/dev/null; then
    if ls "$TEST2_DIR"/HTTP.ncap* 2>/dev/null; then
        echo -e "${GREEN}✓ PASS: HTTP audit records still created despite TCP exclusion${NC}"
    else
        echo -e "${RED}✗ FAIL: HTTP audit records should exist (encapsulated in excluded TCP)${NC}"
        FAILED=1
    fi
fi

if [ -f "$TEST1_DIR"/TLS.ncap* ] 2>/dev/null; then
    if ls "$TEST2_DIR"/TLS.ncap* 2>/dev/null; then
        echo -e "${GREEN}✓ PASS: TLS audit records still created despite TCP exclusion${NC}"
    else
        echo -e "${RED}✗ FAIL: TLS audit records should exist (encapsulated in excluded TCP)${NC}"
        FAILED=1
    fi
fi

if [ -f "$TEST1_DIR"/DNS.ncap* ] 2>/dev/null; then
    if ls "$TEST2_DIR"/DNS.ncap* 2>/dev/null; then
        echo -e "${GREEN}✓ PASS: DNS audit records still created despite UDP exclusion${NC}"
    else
        echo -e "${RED}✗ FAIL: DNS audit records should exist (encapsulated in excluded UDP)${NC}"
        FAILED=1
    fi
fi
echo

# Test 3: Exclude only TCP
echo -e "${YELLOW}Test 3: Exclude only TCP (keep Ethernet, IPv4)${NC}"
TEST3_DIR="$TEST_DIR/test3-exclude-tcp-only"
mkdir -p "$TEST3_DIR"

./bin/net capture -read "$PCAP_FILE" -out "$TEST3_DIR" -exclude TCP 2>&1 | tail -5

echo "Files created with only TCP excluded:"
ls -lh "$TEST3_DIR" | grep -E '\.ncap(\.gz)?$' || true
echo

# Verify Ethernet and IPv4 ARE present
if ls "$TEST3_DIR"/Ethernet.ncap* 2>/dev/null; then
    echo -e "${GREEN}✓ PASS: Ethernet audit records still created${NC}"
else
    echo -e "${RED}✗ FAIL: Ethernet audit records should exist${NC}"
    FAILED=1
fi

if ls "$TEST3_DIR"/IPv4.ncap* 2>/dev/null; then
    echo -e "${GREEN}✓ PASS: IPv4 audit records still created${NC}"
else
    echo -e "${RED}✗ FAIL: IPv4 audit records should exist${NC}"
    FAILED=1
fi

# Verify TCP is NOT present
if ls "$TEST3_DIR"/TCP.ncap* 2>/dev/null; then
    echo -e "${RED}✗ FAIL: TCP audit records should NOT exist${NC}"
    FAILED=1
else
    echo -e "${GREEN}✓ PASS: TCP audit records correctly excluded${NC}"
fi

# Verify HTTP still works (if it was in baseline)
if [ -f "$TEST1_DIR"/HTTP.ncap* ] 2>/dev/null; then
    if ls "$TEST3_DIR"/HTTP.ncap* 2>/dev/null; then
        echo -e "${GREEN}✓ PASS: HTTP audit records still work without TCP decoder${NC}"
    else
        echo -e "${RED}✗ FAIL: HTTP should still work via TCP reassembly${NC}"
        FAILED=1
    fi
fi

echo
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests PASSED!${NC}"
    echo
    echo "Conclusion: The -exclude flag works correctly."
    echo "- Excluded decoders don't create audit record files"
    echo "- Encapsulated layers are still decoded properly"
    echo "- Stream reassembly works independent of packet decoder exclusion"
else
    echo -e "${RED}Some tests FAILED!${NC}"
    echo
    echo "Please review the implementation to ensure:"
    echo "1. Excluded decoders are removed from initialization"
    echo "2. Packet decoding by gopacket is independent of decoder registration"
    echo "3. Stream reassembly uses gopacket's decoded layers, not netcap decoders"
fi
echo "=========================================="

exit $FAILED

