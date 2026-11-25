# Netcap Makefile -- test and coverage entrypoints.
#
# Building, releasing, code generation and the Docker images are driven by
# zeus, not by this file: see zeus/commands.yml (`zeus` with no arguments
# lists the 81 commands). Run `make test-help` for the targets below.

.PHONY: test test-unit test-integration test-regression test-e2e test-bench test-fuzz test-all
.PHONY: test-coverage test-coverage-html test-coverage-check test-race test-determinism test-wireshark
.PHONY: test-golden-update test-regression-verify
.PHONY: test-hyperscan test-msan test-pkg test-verbose test-clean test-help
.PHONY: docs-check docs-source-check recheck-v01612 recheck-v01613 demo-pcaps try-parity try-webui alert-budgets

NETCAP_BIN ?= ./net
DOCS_TEST_TAGS ?= nodpi,noyara

FIREWALL_RELEASE_VERSION ?= 0.1.0-rc.local
FIREWALL_RELEASE_OUTPUT ?= $(TMPDIR)netcap-firewall-candidate
.PHONY: firewall-release-test firewall-release-rehearsal firewall-release-build
firewall-release-test:
	python3 -m unittest discover -s scripts -p test_firewall_release.py -v

firewall-release-rehearsal:
	FIREWALL_RELEASE_INTEGRATION=1 python3 -m unittest discover -s scripts -p test_firewall_release.py -v

firewall-release-build:
	python3 scripts/firewall_release_build.py binaries --version "$(FIREWALL_RELEASE_VERSION)" --output "$(FIREWALL_RELEASE_OUTPUT)"

docs-check:
	python3 scripts/check-docs.py --net "$(NETCAP_BIN)"

docs-source-check:
	GOWORK=off go test -tags "$(DOCS_TEST_TAGS)" ./tests/documentation -count=1

# Test targets
test: test-unit

.PHONY: test-firewall-operations
test-firewall-operations:
	sh scripts/test-firewall-operations.sh

FIREWALL_PACKAGES = ./cmd/netcap-firewall ./cmd/firewall ./internal/waf ./internal/policy ./internal/policystate ./internal/policycontrol ./internal/gateway ./internal/enforcer ./internal/networkfirewall ./internal/transparentfirewall ./internal/firewallstate ./internal/firewallfleet ./internal/firewalltransport ./internal/responseactions ./internal/runtimeobs
.PHONY: test-firewall-ship
test-firewall-ship: test-firewall-operations
	go test -count=1 -race $(FIREWALL_PACKAGES)
	go test -count=1 -race -tags coraza,http3 $(FIREWALL_PACKAGES)
	go vet $(FIREWALL_PACKAGES)
	go vet -tags coraza,http3 $(FIREWALL_PACKAGES)

test-all: test-unit test-integration test-regression

# Unit tests (fast, isolated, with mocks)
test-unit:
	@echo "Running unit tests..."
	go test -short -race -coverprofile=coverage.out ./...

# Integration tests (with real files and fixtures)
test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration ./tests/integration/...

# Download checksum-pinned samples once. The NetMon SIP conversion needs editcap.
test-wireshark:
	python3 scripts/fetch-wireshark-samples.py
	NETCAP_WIRESHARK_CORPUS=tests/wireshark-corpus go test -count=1 -v -timeout=30m -run '^TestWiresharkCorpus$$' ./internal/collector/

# Regression tests compare complete captures across worker counts and runs.
test-regression:
	@echo "Running regression tests..."
	go test ./internal/collector -run '^TestUltimatePCAP(WorkerInvariance|Repeatability)$$' -count=1

test-regression-verify:
	@echo "Verifying regression test outputs..."
	@./scripts/verify-golden-files.sh

# Update golden files (use after verifying changes are correct)
test-golden-update:
	@echo "No golden-update suite is registered; tests/regression does not exist. Review the affected fixture and test directly."
	@exit 2

# E2E tests (full CLI workflows)
test-e2e:
	@echo "Running end-to-end tests..."
	go test -v -tags=e2e -timeout=10m ./tests/e2e/...

# Hyperscan / Vectorscan integration tests (requires libhs from
# pkg-config). Builds with the `hyperscan` tag and exercises the
# multi-pattern fast path used by service probe matching.
test-hyperscan:
	@echo "Running Hyperscan integration tests (requires libhs / vectorscan)..."
	@pkg-config --exists libhs || (echo "libhs not found via pkg-config. Install vectorscan (brew install vectorscan) or hyperscan (apt install libhyperscan-dev)." && exit 1)
	CGO_ENABLED=1 go test -v -tags hyperscan \
		./internal/hsmatch/... \
		./internal/filter/... \
		./internal/decoder/stream/service/... \
		./internal/decoder/stream/software/... \
		./internal/rules/...

# Performance benchmarks. Scoped to ./... because the 235 Benchmark functions
# live beside the code they measure (internal/collector/, internal/netio/, ...);
# tests/benchmarks/ is empty and matches no packages.
test-bench:
	@echo "Running benchmarks..."
	go test -run '^$$' -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./...
	@echo "Profiles saved: cpu.prof, mem.prof"

# Fuzzing smoke run. Each Fuzz* target is gated behind the `fuzz` build tag
# so it never slows the default unit suite. Go's -fuzz flag only accepts a
# single target per invocation, so we discover and loop over every target.
# Override the per-target budget with FUZZTIME (default 10s).
FUZZTIME ?= 10s
FUZZ_PKGS := ./internal/decoder/packet/... ./internal/decoder/stream/smtp/... ./internal/decoder/stream/pop3/... ./internal/decoder/stream/kerberosaudit/...
test-fuzz:
	@echo "Running fuzz smoke (FUZZTIME=$(FUZZTIME) per target)..."
	@for pkg in $(FUZZ_PKGS); do \
		targets=$$(go test -tags fuzz -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz'); \
		for t in $$targets; do \
			echo ">> $$pkg $$t"; \
			go test -tags fuzz -run '^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done
	@echo "Fuzz smoke complete."

# Coverage reports
test-coverage:
	@echo "Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-coverage-html:
	@echo "Generating HTML coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Race detector
test-race:
	@echo "Running tests with race detector..."
	go test -race ./...

# Full-output repeatability and worker-count invariance on the protocol corpus.
test-determinism:
	@echo "Checking deterministic output with the Ultimate PCAP..."
	NETCAP_REQUIRE_ULTIMATE_PCAP=1 go test -count=1 -v -timeout=20m \
		-run '^TestUltimatePCAP(Repeatability|WorkerInvariance)$$' ./internal/collector/

# Memory sanitizer (requires clang)
test-msan:
	@echo "Running tests with memory sanitizer..."
	CC=clang go test -msan ./...

# Test specific package
test-pkg:
	@test -n "$(PKG)" || (echo "Usage: make test-pkg PKG=./internal/collector/" && exit 1)
	go test -v -race -cover $(PKG)

# Test with verbose output
test-verbose:
	go test -v ./...

# Coverage enforcement (fail if below threshold)
test-coverage-check: test-coverage
	@echo "Checking coverage threshold (80%)..."
	@go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//' | \
	  awk '{if ($$1 < 80) {print "Coverage below 80%: " $$1 "%"; exit 1} else {print "Coverage OK: " $$1 "%"}}'

# Clean test artifacts
test-clean:
	@echo "Cleaning test artifacts..."
	rm -f coverage.out coverage.html
	rm -f cpu.prof mem.prof
	rm -rf tests/fixtures/tmp/
	find . -name "*.test" -delete

# Help
# v0.16.12 evaluator follow-up gate. MIXED_UPLOAD_ARCHIVE (the pinned
# v0.16.9 synthetic archive) adds the default-on auxiliary scheduling probe.
RECHECK_TAGS := nodpi,noyara,nomagika
RECHECK_PKGS := ./internal/auditname ./internal/rules ./internal/mcp ./internal/delimited \
	./internal/decoder/stream ./internal/decoder/stream/service ./internal/decoder/stream/utils ./cmd/capture/webui
recheck-v01612:
	GOWORK=off go test -tags $(RECHECK_TAGS) -count=1 $(RECHECK_PKGS) ./internal/collector ./internal/decoder/packet ./cmd/transform
	GOWORK=off go test -race -tags $(RECHECK_TAGS) -count=1 $(RECHECK_PKGS)
	GOWORK=off go test -tags=e2e,$(RECHECK_TAGS) ./tests/e2e -run '^(TestRecheck1612CLI|TestHuntCLIRegressions)$$' -count=1 -timeout=10m
	@if [ -n "$(MIXED_UPLOAD_ARCHIVE)" ]; then \
		GOWORK=off go build -tags $(RECHECK_TAGS) -o $(TMPDIR)net-recheck ./cmd/net && \
		uv run --script scripts/check-mcp-stdio.py $(TMPDIR)net-recheck --mixed-upload-archive "$(MIXED_UPLOAD_ARCHIVE)" --full-fanout; \
	fi

# v0.16.13 follow-up: rules, alerts, stored-TCP passes, capture input.
RECHECK1613_PKGS := ./internal/aggregate ./internal/decoder/stream/tcp ./internal/decoder/stream/tls \
	./internal/decoder/stream/ftp ./internal/decoder/stream/file ./internal/decoder/stream/secret \
	./internal/decoder/stream/dcerpc ./internal/durable ./internal/exitcode ./types
recheck-v01613: recheck-v01612
	GOWORK=off go test -tags $(RECHECK_TAGS) -count=1 $(RECHECK1613_PKGS)
	GOWORK=off go test -tags appstore,$(RECHECK_TAGS) -count=1 ./cmd/capture/webui
	GOWORK=off go test -tags=e2e,$(RECHECK_TAGS) ./tests/e2e -run '^TestServicePartialCapture$$' -count=1 -timeout=10m

# Replay 7 synthetic captures through the embedded rules and check the
# evaluator's noise budgets and coverage floors (netcap-eval-scoring checkout).
EVAL_SCORING ?= ../netcap-eval-scoring
alert-budgets:
	/bin/bash $(EVAL_SCORING)/tools/alert_tuning/run_synthetic_check.sh .

# Analyze captures through the MCP/WebUI pipeline the try demo uses; every
# input must complete. Defaults to the captures that regressed in v0.16.12.
DEMO_PCAPS ?= pcaps/arp-dns-eth-icmp-ip-udp-goodhttp-gooddns.pcapng \
	pcaps/malware-traffic-analysis.net/2017-10-13-Blank-Slate-campaign-pushes-Sage-2.2-ransomware.pcap \
	pcaps/testfiles/ultimate-PCAP-v20250325.pcapng pcaps/testfiles/merged.pcapng
demo-pcaps:
	GOWORK=off go build -tags $(RECHECK_TAGS) -o $(TMPDIR)net-demo ./cmd/net
	uv run --script scripts/check-demo-pcaps.py $(TMPDIR)net-demo $(DEMO_PCAPS)

# Replay the 20 try.netcap.io captures (scripts/try-pcaps.json) through
# service mode with try's flags. TRY_DPI=true for a DPI build.
TRY_DPI ?= false
TRY_BINARY ?=
TRY_CHECK_FLAGS ?=
try-parity:
	@if [ -n "$(TRY_BINARY)" ]; then \
		python3 scripts/check-service-pcaps.py "$(TRY_BINARY)" --dpi $(TRY_DPI) $(TRY_CHECK_FLAGS); \
	elif [ "$(TRY_DPI)" = true ]; then \
		printf '%s\n' 'Set TRY_BINARY to a DPI-enabled build before using TRY_DPI=true' >&2; exit 2; \
	else \
		GOWORK=off go build -tags $(RECHECK_TAGS) -o $(TMPDIR)net-try ./cmd/net && \
		python3 scripts/check-service-pcaps.py $(TMPDIR)net-try --dpi false $(TRY_CHECK_FLAGS); \
	fi

# Test the browser against the bundle actually embedded by net capture --service.
try-webui:
	@set -eu; \
	if [ -n "$(TRY_BINARY)" ]; then \
		python3 scripts/check-service-pcaps.py "$(TRY_BINARY)" --dpi $(TRY_DPI) --webui --timeout 60; \
	else \
		tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/netcap-try-build.XXXXXX"); \
		frontend=cmd/capture/webui/frontend; \
		placeholder=$$frontend/dist/MODULE_PLACEHOLDER.txt; \
		if [ -f "$$placeholder" ]; then cp "$$placeholder" "$$tmp/placeholder"; fi; \
		trap 'if [ -f "$$tmp/placeholder" ]; then cp "$$tmp/placeholder" "$$placeholder"; fi; rm -rf "$$tmp"' EXIT; \
		env -i PATH="$$PATH" HOME="$$HOME" TMPDIR="$${TMPDIR:-/tmp}" COREPACK_ENABLE_NETWORK=0 \
			pnpm --dir "$$frontend" run build --mode e2e; \
		GOWORK=off go build -tags $(RECHECK_TAGS) -o "$$tmp/net" ./cmd/net; \
		python3 scripts/check-service-pcaps.py "$$tmp/net" --dpi false --webui --timeout 60; \
	fi

test-help:
	@echo "Netcap Test Targets:"
	@echo ""
	@echo "  test              - Run unit tests (default)"
	@echo "  test-all          - Run unit, integration, and regression tests"
	@echo "  test-unit         - Run fast unit tests"
	@echo "  test-integration  - Run integration tests"
	@echo "  test-regression   - Run regression tests"
	@echo "  test-e2e          - Run end-to-end tests"
	@echo "  test-bench        - Run performance benchmarks"
	@echo "  test-fuzz         - Run fuzz smoke over all Fuzz* targets (FUZZTIME=10s)"
	@echo ""
	@echo "  test-coverage     - Generate coverage report"
	@echo "  test-coverage-html - Generate HTML coverage report"
	@echo "  test-race         - Run tests with race detector"
	@echo "  test-determinism  - Compare Ultimate PCAP output across runs and worker counts"
	@echo "  test-wireshark    - Fetch verified Wireshark samples and run the full corpus (needs editcap)"
	@echo "  recheck-v01612    - v0.16.12 evaluator follow-up gate (MIXED_UPLOAD_ARCHIVE= adds scheduling)"
	@echo "  recheck-v01613    - v0.16.13 follow-up gate; runs recheck-v01612 first"
	@echo "  alert-budgets     - rule noise budgets on synthetic captures (needs ../netcap-eval-scoring)"
	@echo "  demo-pcaps        - Analyze DEMO_PCAPS through the try-demo MCP/WebUI pipeline"
	@echo "  try-parity        - Replay the 20 try.netcap.io captures through service mode"
	@echo "  try-webui         - Check the embedded Try UI in Chrome with two synthetic captures"
	@echo ""
	@echo "  test-golden-update    - Retired; fails explicitly (no registered suite)"
	@echo "  test-regression-verify - Verify against golden files"
	@echo ""
	@echo "  test-hyperscan    - Hyperscan/Vectorscan tests (needs libhs)"
	@echo "  test-pkg PKG=./internal/collector/ - Test specific package"
	@echo "  test-verbose      - Run tests with verbose output"
	@echo "  test-clean        - Clean test artifacts"
	@echo ""
	@echo "Building and releasing is zeus, not make: see zeus/commands.yml"

-include operations.Makefile
