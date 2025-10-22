# Testing Quick Start Guide

This guide helps you get started with the Netcap test suite.

## 📋 What Was Created

The test infrastructure includes:

### Documentation
- `docs/TEST_PLAN.md` - Comprehensive 16-week test plan
- `docs/TEST_PLAN_SUMMARY.md` - Executive summary
- `docs/TESTING_QUICKSTART.md` - This file
- `tests/README.md` - Test suite documentation

### Infrastructure
- `tests/` - Test directory structure
  - `fixtures/` - Test data (PCAPs, golden files, configs, databases)
  - `integration/` - Integration tests
  - `regression/` - Regression tests
  - `e2e/` - End-to-end tests
  - `benchmarks/` - Performance tests
  - `helpers/` - Test utilities

### Utilities
- `tests/helpers/fixtures.go` - Fixture loading and golden file management
- `tests/helpers/pcap_generator.go` - Synthetic PCAP generation
- `tests/TEMPLATE_test.go` - Test template with examples
- `Makefile.test` - Test automation targets
- `scripts/verify-golden-files.sh` - Golden file verification

### Examples
- `tests/integration/example_integration_test.go` - Integration test example
- `tests/regression/example_regression_test.go` - Regression test example

## 🚀 Quick Start

### 1. Run Existing Tests

```bash
# Run all unit tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test -v ./collector/

# Run with race detector
go test -race ./...
```

### 2. Using the Makefile

```bash
# View all test targets
make -f Makefile.test test-help

# Run unit tests
make -f Makefile.test test-unit

# Run with coverage report
make -f Makefile.test test-coverage-html
# Opens coverage.html in browser

# Run integration tests
make -f Makefile.test test-integration

# Run regression tests
make -f Makefile.test test-regression

# Run benchmarks
make -f Makefile.test test-bench
```

### 3. Writing Your First Test

**Option A: Use the Template**

```bash
# Copy the template
cp tests/TEMPLATE_test.go decoder/packet/myprotocol_test.go

# Edit and implement your test
vim decoder/packet/myprotocol_test.go

# Run your test
go test -v ./decoder/packet/ -run TestMyProtocol
```

**Option B: Start from Scratch**

```go
package mypackage_test

import "testing"

func TestMyFeature(t *testing.T) {
    // Arrange
    input := "test"
    
    // Act
    result := MyFunction(input)
    
    // Assert
    if result != "expected" {
        t.Errorf("got %v, want %v", result, "expected")
    }
}
```

## 📊 Current Status

### Coverage by Package (as of Oct 2025)

| Package | Coverage | Status |
|---------|----------|--------|
| logger | 89.5% | ✅ Excellent |
| delimited | 69.0% | ✅ Good |
| reassembly | 68.9% | ⚠️ 4 failing tests |
| encoder | 64.0% | ✅ Good |
| credentials | 52.8% | ⚠️ Medium |
| label/manager | 49.3% | ⚠️ Medium |
| io | 19.7% | ❌ Low |
| **Most packages** | 0-5% | ❌ Critical |

### Immediate Priorities

1. **Fix Build Errors** (Week 1)
   - [ ] Fix DBS package unused variables
   - [ ] Fix 4 failing reassembly tests
   - [ ] Resolve DPI build issues
   - [ ] Fix resolver test data issues

2. **Core Package Tests** (Weeks 2-4)
   - [ ] Collector: 85% coverage
   - [ ] Types: 80% coverage
   - [ ] Decoder/packet: 75% coverage
   - [ ] I/O: 85% coverage

## 🔧 Common Tasks

### Add Test for New Decoder

```bash
# 1. Create test file
cat > decoder/packet/mynewprotocol_test.go << 'EOF'
package packet_test

import (
    "testing"
    "github.com/dreadl0ck/netcap/decoder/packet"
)

func TestMyNewProtocol_Decode(t *testing.T) {
    // Your test here
}
EOF

# 2. Add test PCAP
cp mynewprotocol.pcap tests/fixtures/pcaps/protocols/

# 3. Run test
go test -v ./decoder/packet/ -run TestMyNewProtocol
```

### Create Integration Test

```bash
# 1. Create test file
cat > tests/integration/myfeature_test.go << 'EOF'
// +build integration

package integration

import "testing"

func TestIntegration_MyFeature(t *testing.T) {
    // Multi-component test
}
EOF

# 2. Run integration tests
go test -tags=integration -v ./tests/integration/
```

### Add Regression Test with Golden File

```bash
# 1. Process PCAP to generate output
go run cmd/*.go capture -r test.pcap -out /tmp/test-output

# 2. Save as golden file
mkdir -p tests/fixtures/golden/csv/my_scenario/
cp /tmp/test-output/HTTP.csv tests/fixtures/golden/csv/my_scenario/

# 3. Create regression test
cat > tests/regression/mytest_test.go << 'EOF'
// +build regression

package regression

import (
    "testing"
    "github.com/dreadl0ck/netcap/tests/helpers"
)

func TestRegression_MyScenario(t *testing.T) {
    loader := helpers.NewFixtureLoader(helpers.TestDataPath())
    
    // Generate output
    // var got []byte
    
    // Compare with golden
    want, err := loader.LoadGoldenFile("HTTP", "csv", "my_scenario")
    if err != nil {
        t.Skip("Golden file not found:", err)
    }
    
    helpers.CompareCSV(t, got, want)
}
EOF

# 4. Run regression test
go test -tags=regression -v ./tests/regression/
```

### Generate Test PCAP Programmatically

```go
package main

import (
    "github.com/dreadl0ck/netcap/tests/helpers"
)

func main() {
    // Generate HTTP request PCAP
    err := helpers.GenerateHTTPRequest("test-http.pcap", "example.com")
    if err != nil {
        panic(err)
    }
    
    // Generate TCP handshake
    err = helpers.GenerateTCPHandshake(
        "test-tcp.pcap",
        "192.168.1.1", "192.168.1.2",
        12345, 80,
    )
    if err != nil {
        panic(err)
    }
}
```

## 🐛 Troubleshooting

### Build Failures

**Problem:** Tests fail to compile

```bash
# Check for syntax errors
go vet ./...

# Check imports
go mod tidy

# Rebuild everything
go clean -cache
go build ./...
```

**Problem:** Missing dependencies

```bash
# Update dependencies
go mod download
go mod tidy
```

### Test Failures

**Problem:** Test fails intermittently (flaky test)

```bash
# Run test multiple times
go test -count=10 -run TestMyFlaky ./...

# Run with race detector
go test -race -run TestMyFlaky ./...
```

**Problem:** Test hangs

```bash
# Run with timeout
go test -timeout=30s ./...

# Add verbose output
go test -v -timeout=30s ./...
```

### Missing Test Data

**Problem:** "Test PCAP not available" or "Golden file not found"

```bash
# Check if fixture exists
ls tests/fixtures/pcaps/protocols/

# Download test fixtures (if script exists)
make -f Makefile.test fixtures-download

# Or skip tests requiring fixtures
go test -short ./...
```

### Golden File Mismatches

**Problem:** Regression test fails with "Files differ"

```bash
# View the difference
diff tests/fixtures/golden/csv/scenario/HTTP.csv /tmp/actual-output/HTTP.csv

# If change is intentional, update golden file
UPDATE_GOLDEN=1 go test -tags=regression -v ./tests/regression/

# Or manually
cp /tmp/actual-output/HTTP.csv tests/fixtures/golden/csv/scenario/
```

## 📈 Tracking Progress

### Check Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View in terminal
go tool cover -func=coverage.out

# View in browser
go tool cover -html=coverage.out
```

### Run Coverage Check

```bash
# Ensure coverage doesn't drop below threshold
make -f Makefile.test test-coverage-check
```

### Benchmark Performance

```bash
# Run benchmarks
go test -bench=. ./...

# With memory stats
go test -bench=. -benchmem ./...

# Save results for comparison
go test -bench=. -benchmem ./... | tee benchmark-results.txt
```

## 🎯 Test Development Workflow

### For New Features

1. **Write test first** (TDD approach)
   ```bash
   # Create test
   vim mypackage/myfeature_test.go
   
   # Run (should fail)
   go test ./mypackage/
   ```

2. **Implement feature**
   ```bash
   vim mypackage/myfeature.go
   ```

3. **Verify test passes**
   ```bash
   go test -v ./mypackage/
   ```

4. **Check coverage**
   ```bash
   go test -cover ./mypackage/
   ```

### For Bug Fixes

1. **Write failing test** reproducing the bug
2. **Fix the bug**
3. **Verify test now passes**
4. **Add to regression suite** (if needed)

### For Refactoring

1. **Ensure existing tests pass**
   ```bash
   go test ./...
   ```

2. **Make refactoring changes**

3. **Run tests continuously**
   ```bash
   # Use entr or similar for auto-run
   find . -name '*.go' | entr -c go test ./...
   ```

4. **Verify coverage maintained**

## 📚 Additional Resources

- [Full Test Plan](TEST_PLAN.md) - Comprehensive 16-week plan
- [Test Plan Summary](TEST_PLAN_SUMMARY.md) - Executive overview
- [Test Suite README](../tests/README.md) - Detailed test documentation
- [Go Testing Documentation](https://golang.org/pkg/testing/)
- [Table-Driven Tests in Go](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)

## 🤝 Contributing Tests

When submitting PRs:

1. ✅ Add tests for new features
2. ✅ Update tests for bug fixes
3. ✅ Maintain or improve coverage
4. ✅ Ensure all tests pass
5. ✅ Update documentation if needed
6. ✅ Follow test naming conventions

### Test Naming Convention

```go
// Format: Test<Component>_<Scenario>
func TestCollector_InitWithValidConfig(t *testing.T)
func TestDecoder_MalformedPacket(t *testing.T)
func TestHTTP_ParseRequest(t *testing.T)

// Format: Benchmark<Component>_<Operation>
func BenchmarkCollector_ProcessPacket(b *testing.B)
func BenchmarkDecoder_TCP(b *testing.B)
```

## 🎓 Learning Path

### Week 1: Basics
- Run existing tests
- Read test examples
- Write simple unit test

### Week 2: Test Types
- Write table-driven test
- Create integration test
- Use test fixtures

### Week 3: Advanced
- Add regression test
- Generate synthetic PCAP
- Create benchmark

### Week 4: Contribution
- Fix failing test
- Improve coverage
- Submit PR with tests

---

**Questions?** Open an issue on GitHub or check the full [TEST_PLAN.md](TEST_PLAN.md)

**Last Updated:** October 21, 2025

