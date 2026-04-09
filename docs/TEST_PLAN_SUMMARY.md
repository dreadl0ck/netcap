# Netcap Test Plan - Executive Summary

**Status:** Draft  
**Created:** October 21, 2025  
**Full Plan:** [TEST_PLAN.md](TEST_PLAN.md)

## Current State

### Coverage Status
- **Overall Coverage:** ~15-20% (estimated from test run)
- **Critical Gaps:**
  - 66 packet decoders: Mostly untested
  - 63+ stream decoders: Mostly untested  
  - All 9 CLI commands: 0% coverage
  - Types package: 0.8% coverage
  - Collector package: Build failures

### Issues
- ❌ 4 failing reassembly tests
- ❌ Multiple build failures (DPI, DBS, collector)
- ❌ Missing test data (Bleve indices, DHCP fingerprints)
- ⚠️ No regression test suite
- ⚠️ No E2E tests for CLI commands

## Target State

### Coverage Goals
- **Overall:** 80%+
- **Critical packages:** 85%+ (collector, decoder, types)
- **Important packages:** 75%+ (io, reassembly)
- **Commands:** 60%+

### Test Categories
1. **Unit Tests (55%)** - Fast, isolated, with mocks
2. **Integration Tests (15%)** - Multi-component tests
3. **Regression Tests (15%)** - Golden file comparisons
4. **Performance Tests (10%)** - Benchmarks
5. **E2E Tests (5%)** - Full CLI workflows

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)
**Goal:** Fix bugs, establish infrastructure, 40% coverage

- ✅ Fix failing tests and build errors
- ✅ Create test directory structure
- ✅ Build test helpers and utilities
- ✅ Test critical packages (collector, types, io)

### Phase 2: Core Coverage (Weeks 5-8)
**Goal:** 70% coverage on critical paths

- ✅ Test priority protocol decoders (Tier 1 & 2)
- ✅ Test stream decoders (HTTP, TLS, SSH, etc.)
- ✅ Enhance reassembly tests to 90%
- ✅ Create integration test suite

### Phase 3: Regression & Commands (Weeks 9-12)
**Goal:** Regression suite + CLI coverage, 75% overall

- ✅ Build golden file suite for all protocols
- ✅ Test all CLI commands
- ✅ Create performance baselines
- ✅ E2E workflow tests

### Phase 4: Completeness (Weeks 13-16)
**Goal:** 80%+ coverage, comprehensive suite

- ✅ Test remaining protocol decoders
- ✅ Edge cases and malformed packets
- ✅ Stress and performance tests
- ✅ Documentation and guides

## Quick Wins (Week 1)

Priority fixes that unblock testing:

1. **Fix DBS Build Error** (~30 min)
   - Remove unused variables in `dbs/server.go:180-181`

2. **Fix Reassembly Tests** (~2 hours)
   - Debug and fix 4 failing KeepSimple tests
   - Issue appears to be with byte buffer boundaries

3. **Provide Test Data** (~1 hour)
   - Create minimal test databases for resolvers
   - Mock missing Bleve indices or make tests fallback gracefully

4. **Fix Collector Tests** (~1 hour)
   - Resolve build failures
   - Ensure basic collector test passes

## Test Infrastructure

### Directory Structure
```
tests/
├── fixtures/          # Test data
│   ├── pcaps/        # Protocol-specific PCAPs
│   ├── golden/       # Expected outputs
│   └── databases/    # Test DB files
├── integration/      # Integration tests
├── regression/       # Regression tests
├── e2e/             # End-to-end tests
├── benchmarks/      # Performance tests
└── helpers/         # Test utilities
```

### Running Tests
```bash
make test-unit              # Fast unit tests
make test-integration       # Integration tests
make test-regression        # Regression tests
make test-all              # All tests
make test-coverage         # Coverage report
make test-bench            # Benchmarks
```

## Key Metrics

### Success Criteria
- ✅ 80%+ code coverage
- ✅ 0 flaky tests
- ✅ All tests pass on clean checkout
- ✅ Unit tests < 30s
- ✅ Full suite < 15min

### Quality Targets
- Regression detection for protocol changes
- Performance regression detection (>10% slower)
- Clear, actionable test failures
- Easy to add new tests

## Resources Required

### Developer Time
- **Phase 1-2:** 1 developer, 8 weeks (foundation + core)
- **Phase 3-4:** 0.5-1 developer, 8 weeks (completion)
- **Maintenance:** Ongoing as features added

### Test Data
- ~100 MB test PCAPs (essential fixtures)
- Synthetic PCAP generation for protocols
- Minimal test databases (~50 MB)

### Infrastructure
- CI/CD integration (GitHub Actions)
- Coverage tracking (Codecov)
- Artifact storage for large test files

## Benefits

### Immediate
- Catch bugs before release
- Confidence in refactoring
- Faster debugging

### Long-term
- Prevent regressions
- Safer protocol additions
- Performance tracking
- Documentation through tests

## Next Steps

1. **Review and approve** this test plan
2. **Assign ownership** for test implementation
3. **Fix critical issues** (Week 1 quick wins)
4. **Begin Phase 1** implementation
5. **Track progress** against roadmap

## Questions?

- See full plan: [TEST_PLAN.md](TEST_PLAN.md)
- Test utilities: [tests/README.md](../tests/README.md)
- Contributing: Open GitHub issue for questions

---

**Approvals:**
- [ ] Technical Lead
- [ ] Project Maintainer
- [ ] CI/CD Owner

**Last Updated:** October 21, 2025

