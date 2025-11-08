#!/bin/bash

# Test runner script for autocomplete unit tests
# This script installs dependencies and runs the tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================"
echo "Netcap Autocomplete Test Runner"
echo "======================================"
echo ""

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    echo ""
fi

# Check what test to run
TEST_TYPE="${1:-all}"

case "$TEST_TYPE" in
    "logic")
        echo "🧪 Running autocomplete logic tests..."
        npm test -- autocomplete-logic
        ;;
    "keyboard")
        echo "⌨️  Running keyboard behavior tests..."
        npm test -- keyboard-behavior
        ;;
    "component")
        echo "🔧 Running component integration tests..."
        npm test -- audit-autocomplete
        ;;
    "watch")
        echo "👀 Running tests in watch mode..."
        npm run test:watch
        ;;
    "coverage")
        echo "📊 Running tests with coverage..."
        npm run test:coverage
        ;;
    "all")
        echo "🚀 Running all autocomplete tests..."
        npm test -- __tests__/
        ;;
    *)
        echo "❌ Unknown test type: $TEST_TYPE"
        echo ""
        echo "Usage: ./run-tests.sh [logic|keyboard|component|watch|coverage|all]"
        echo ""
        echo "Options:"
        echo "  logic      - Run pure logic tests only"
        echo "  keyboard   - Run keyboard behavior tests only"
        echo "  component  - Run component integration tests only"
        echo "  watch      - Run tests in watch mode"
        echo "  coverage   - Run tests with coverage report"
        echo "  all        - Run all tests (default)"
        exit 1
        ;;
esac

echo ""
echo "✅ Tests completed!"

