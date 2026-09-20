//go:build appstore

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppStoreDoesNotRegisterDirectOnlyRoutes(t *testing.T) {
	mux := http.NewServeMux()
	registerEditionRoutes(mux, &Server{})
	for _, path := range []string{
		"/api/dbs",
		"/api/dbs/update",
		"/api/dpi",
		"/api/dpi/preferences",
		"/api/yara/status",
		"/api/yara/rules",
		"/api/yara/rules/example.yar",
		"/api/yara/scan",
		"/api/yara/scan-file",
		"/api/service-probes",
		"/api/service-probes/example",
		"/api/service-probes/test",
		"/api/service-probes/export",
		"/api/service-probes/import",
		"/api/injection-rules",
		"/api/injection-rules/example",
		"/api/injection-events",
		"/api/injection-events/clear",
		"/api/injection-stats",
		"/api/injection-actions",
		"/api/network-interfaces",
		"/api/stop-capture",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s returned %d, want 404", path, response.Code)
		}
	}
}

func TestAppStoreDependencyGraphExcludesDBs(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	ctx := build.Default
	ctx.BuildTags = []string{"appstore", "nodpi", "noyara", "nomagika"}
	visited := make(map[string]bool)
	var visit func(string)
	visit = func(dir string) {
		pkg, err := ctx.ImportDir(dir, build.IgnoreVendor)
		if err != nil {
			t.Fatalf("load appstore package %s: %v", dir, err)
		}
		if visited[pkg.ImportPath] {
			return
		}
		visited[pkg.ImportPath] = true

		for _, imported := range pkg.Imports {
			if imported == "github.com/dreadl0ck/netcap/dbs" || imported == "os/exec" {
				t.Fatalf("appstore dependency %s imports forbidden package %s", pkg.ImportPath, imported)
			}
			const module = "github.com/dreadl0ck/netcap"
			if imported == module || strings.HasPrefix(imported, module+"/") {
				rel := strings.TrimPrefix(imported, module)
				visit(filepath.Join(repoRoot, filepath.FromSlash(rel)))
			}
		}
	}

	visit(".")
}

func TestAppStoreWebUISourcesDoNotImportOSExec(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if excludedFromAppStoreBuild(string(source)) {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			if importPath(imported) == "os/exec" {
				t.Errorf("%s imports os/exec; the App Store web UI must run analysis in-process", entry.Name())
			}
		}
	}
}

func excludedFromAppStoreBuild(source string) bool {
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//go:build ") {
			if strings.HasPrefix(line, "package ") {
				return false
			}
			continue
		}
		for _, term := range strings.Split(strings.TrimPrefix(line, "//go:build "), "&&") {
			if strings.TrimSpace(term) == "!appstore" {
				return true
			}
		}
		return false
	}
	return false
}

func importPath(spec *ast.ImportSpec) string {
	return strings.Trim(spec.Path.Value, `"`)
}

// TestInProcessAnalysisProducesAuditRecords is the leak-free proof required by
// the App Store edition: with the nodpi,noyara,nomagika tags the nDPI /
// libprotoident leak is compiled out, and this test runs a real pcap through
// the in-process collector end-to-end and asserts audit records land on disk
// without an error log.
//
// It only compiles under the appstore tag, so runAnalysis == runAnalysisInProcess.
func TestInProcessAnalysisProducesAuditRecords(t *testing.T) {
	input := filepath.Join("..", "..", "..", "decoder", "stream", "protobuf", "testdata", "protobuf_tcp_addressbook.pcapng")
	if _, err := os.Stat(input); err != nil {
		t.Fatalf("tracked analysis fixture is missing: %v", err)
	}

	outDir := t.TempDir()

	s := NewServer(
		"127.0.0.1:0",   // addr (server is never started)
		outDir,          // outDir
		[]string{input}, // inputFiles
		"",              // assetsPath
		false,           // debugLogging
		false,           // dpiConfigured
		false,           // isServiceMode -> local mode, sessionManager nil
		nil,             // serviceConfig
		nil,             // runtimeConfig
		false,           // devMode
	)

	job := &AnalysisJob{
		SessionID: "test-inprocess",
		InputFile: input,
		OutputDir: outDir,
		EnableDPI: false, // MAS build has no DPI anyway
	}
	s.mu.Lock()
	s.fileIDToPath[job.SessionID] = input
	s.mu.Unlock()

	// runAnalysis is the in-process path in the appstore build.
	s.runAnalysis(job)

	// A non-empty analysis error log means the run failed.
	if data, err := os.ReadFile(filepath.Join(outDir, analysisErrorLogName)); err == nil && len(data) > 0 {
		t.Fatalf("analysis produced an error log:\n%s", string(data))
	}

	// Assert at least one .ncap/.ncap.gz audit record was written.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	audit := 0
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".ncap") || strings.HasSuffix(n, ".ncap.gz") {
			audit++
		}
	}
	if audit == 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("no audit records produced by in-process analysis; output dir contained: %v", names)
	}
	assertProgressStatus(t, s, job.SessionID, "completed")
	t.Logf("in-process analysis produced %d audit record file(s) from %s", audit, input)
}

func TestAppStoreInProcessAnalysisNeedsNoExternalDatabases(t *testing.T) {
	config := inProcessResolverConfig()
	if config.ServiceDB || config.GeolocationDB {
		t.Fatalf("App Store resolver config requires external databases: %+v", config)
	}
	excluded := getExcludeDecoders(&AnalysisJob{EnableDPI: false})
	for _, decoder := range []string{"Exploit", "Service", "Software"} {
		if !strings.Contains(excluded, decoder) {
			t.Fatalf("App Store analysis initializes database-dependent decoder %s: excludes=%q", decoder, excluded)
		}
	}
}

func TestInProcessAnalysisFailureTerminatesLocalProgress(t *testing.T) {
	input := filepath.Join(t.TempDir(), "invalid.pcap")
	if err := os.WriteFile(input, []byte("not a capture"), 0600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	s := NewServer("127.0.0.1:0", outDir, []string{input}, "", false, false, false, nil, nil, false)
	job := &AnalysisJob{SessionID: "test-inprocess-error", InputFile: input, OutputDir: outDir}
	s.mu.Lock()
	s.fileIDToPath[job.SessionID] = input
	s.mu.Unlock()

	s.runAnalysis(job)

	assertProgressStatus(t, s, job.SessionID, "failed")
}

func assertProgressStatus(t *testing.T, s *Server, fileID, want string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/progress/"+fileID, nil)
	response := httptest.NewRecorder()
	s.handleProgress(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("progress returned %d: %s", response.Code, response.Body.String())
	}
	var progress ProgressInfo
	if err := json.NewDecoder(response.Body).Decode(&progress); err != nil {
		t.Fatal(err)
	}
	if progress.Status != want {
		t.Fatalf("progress status = %q, want %q", progress.Status, want)
	}
}

// TestPureGoPCAPFilterMatches proves the tcpdump replacement works in-process:
// filtering the SSH fixture for the SSH port keeps packets, and an impossible
// filter keeps none — no external process involved.
func TestPureGoPCAPFilterMatches(t *testing.T) {
	input := filepath.Join("..", "..", "..", "decoder", "stream", "protobuf", "testdata", "protobuf_tcp_addressbook.pcapng")
	if _, err := os.Stat(input); err != nil {
		t.Fatalf("tracked filter fixture is missing: %v", err)
	}

	out := filepath.Join(t.TempDir(), "filtered.pcap")
	n, err := filterPCAPToFile(input, "tcp port 18127", out)
	if err != nil {
		t.Fatalf("filterPCAPToFile: %v", err)
	}
	if n == 0 {
		t.Fatal("expected tcp port 18127 to match packets in fixture, got 0")
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() < 24 {
		t.Fatalf("filtered pcap missing or too small: err=%v", err)
	}

	// A valid filter that matches nothing should write nothing and remove the
	// file. 203.0.113.0/24 is TEST-NET-3 (RFC 5737) and will not appear in the
	// fixture.
	out2 := filepath.Join(t.TempDir(), "none.pcap")
	n2, err := filterPCAPToFile(input, "host 203.0.113.213", out2)
	if err != nil {
		t.Fatalf("filterPCAPToFile (no match): %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected non-matching filter to match 0 packets, got %d", n2)
	}
	if _, err := os.Stat(out2); !os.IsNotExist(err) {
		t.Fatalf("expected empty output file to be removed, stat err=%v", err)
	}
}

func TestPureGoPCAPFilterReturnsReadErrors(t *testing.T) {
	input := filepath.Join(t.TempDir(), "truncated.pcap")
	data := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
		0x00, 0x01,
	}
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "filtered.pcap")
	if _, err := filterPCAPToFile(input, "", output); err == nil || !strings.Contains(err.Error(), "read packet") {
		t.Fatalf("filterPCAPToFile error = %v, want packet read error", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("partial output was not removed: %v", err)
	}
}

func TestPureGoPCAPFilterHonorsCancellation(t *testing.T) {
	input := filepath.Join("..", "..", "..", "decoder", "stream", "protobuf", "testdata", "protobuf_tcp_addressbook.pcapng")
	output := filepath.Join(t.TempDir(), "filtered.pcap")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := filterPCAPToFileContext(ctx, input, "", output)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("filterPCAPToFileContext error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("canceled output was not removed: %v", err)
	}
}
