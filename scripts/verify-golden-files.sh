#!/bin/bash
# Script to verify regression test outputs against golden files

set -e

GOLDEN_DIR="tests/fixtures/golden"
OUTPUT_DIR="${1:-/tmp/netcap-regression-output}"

if [ ! -d "$GOLDEN_DIR" ]; then
    echo "Error: Golden files directory not found: $GOLDEN_DIR"
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Output directory not found: $OUTPUT_DIR"
    echo "Run regression tests first to generate output"
    exit 1
fi

echo "Verifying regression test outputs..."
echo "Golden files: $GOLDEN_DIR"
echo "Test output:  $OUTPUT_DIR"
echo ""

ERRORS=0
CHECKED=0

# Function to compare files
compare_files() {
    local golden="$1"
    local output="$2"
    local name="$3"
    
    if [ ! -f "$output" ]; then
        echo "❌ MISSING: $name"
        echo "   Expected output file not found: $output"
        ERRORS=$((ERRORS + 1))
        return
    fi
    
    if diff -q "$golden" "$output" > /dev/null 2>&1; then
        echo "✅ PASS: $name"
    else
        echo "❌ FAIL: $name"
        echo "   Files differ. Run: diff $golden $output"
        ERRORS=$((ERRORS + 1))
    fi
    
    CHECKED=$((CHECKED + 1))
}

# Find and compare all golden files
while IFS= read -r -d '' golden_file; do
    # Get relative path
    rel_path="${golden_file#$GOLDEN_DIR/}"
    output_file="$OUTPUT_DIR/$rel_path"
    
    compare_files "$golden_file" "$output_file" "$rel_path"
done < <(find "$GOLDEN_DIR" -type f -print0)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Verification complete"
echo "  Files checked: $CHECKED"
echo "  Failures:      $ERRORS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "To update golden files after verifying changes:"
    echo "  UPDATE_GOLDEN=1 make test-regression"
    exit 1
fi

echo ""
echo "All regression tests passed! ✅"
exit 0

