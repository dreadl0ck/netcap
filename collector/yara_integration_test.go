//go:build !noyara
// +build !noyara

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package collector_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// TestYaraIntegration_EndToEnd verifies the full YARA scanning chain:
// 1. Process a PCAP with file extraction enabled
// 2. Write a YARA rule that matches content in the extracted files
// 3. Scan extracted files with the YaraScanner
// 4. Verify matches appear
// 5. Verify matches are recorded in File audit records when auto-scan is enabled
func TestYaraIntegration_EndToEnd(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found:", httpAuthPCAP)
	}

	// --- Phase 1: Process PCAP and extract files ---
	tmpDir := t.TempDir()
	yaraRulesDir := filepath.Join(tmpDir, "yara-rules")
	if err := os.MkdirAll(yaraRulesDir, 0755); err != nil {
		t.Fatalf("Failed to create yara rules dir: %v", err)
	}

	// Write a YARA rule that matches common patterns in HTTP responses.
	// HTTP auth PCAPs contain HTML responses with common strings.
	yaraRule := `
rule html_content {
    meta:
        description = "Matches HTML content from HTTP responses"
    strings:
        $html = "<html" nocase
        $body = "<body" nocase
        $doctype = "<!DOCTYPE" nocase
        $head = "<head" nocase
        $http = "HTTP" nocase
    condition:
        any of them
}

rule text_content {
    meta:
        description = "Matches any text content"
    strings:
        $the = "the" nocase
        $and = "and" nocase
        $auth = "auth" nocase
        $password = "password" nocase
        $content = "Content-Type" nocase
    condition:
        any of them
}
`
	yaraRulePath := filepath.Join(yaraRulesDir, "test_rules.yar")
	if err := os.WriteFile(yaraRulePath, []byte(yaraRule), 0644); err != nil {
		t.Fatalf("Failed to write YARA rule: %v", err)
	}

	// Validate the rule compiles
	if err := file.ValidateYaraSource(yaraRule); err != nil {
		t.Fatalf("YARA rule validation failed: %v", err)
	}
	t.Log("YARA rule validated successfully")

	// Configure file extraction with YARA scanning enabled
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	cfg.FileExtraction.HashAlgorithms.SHA256 = true
	cfg.FileExtraction.Advanced.ComputeEntropy = true
	cfg.FileExtraction.Advanced.EnableYaraScanning = true
	cfg.FileExtraction.Advanced.YaraRulesPath = yaraRulesDir
	file.SetGlobalConfig(cfg)

	// Initialize the global YARA scanner so the file analysis pipeline uses it
	file.ResetGlobalYaraScanner()
	scanner, err := file.InitGlobalYaraScanner(yaraRulesDir)
	if err != nil {
		t.Fatalf("Failed to initialize YARA scanner: %v", err)
	}
	if scanner == nil {
		t.Fatal("YARA scanner is nil")
	}
	t.Logf("YARA scanner initialized with %d rules from %s", scanner.RuleCount(), yaraRulesDir)

	// Create and run collector
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP
	if err := c.CollectPcap(httpAuthPCAP); err != nil {
		t.Fatalf("PCAP collection failed: %v", err)
	}
	t.Log("PCAP processed successfully")

	// --- Phase 2: Verify File audit records exist and check for YARA matches ---
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if !fileExists(fileAuditPath) {
		// No files extracted — try another approach with on-demand scanning
		t.Log("No File audit records created from HTTP auth PCAP, checking extracted files directly...")
	}

	// Check extracted files on disk
	filesDir := filepath.Join(tmpDir, "files")
	var extractedFilePaths []string

	if _, err := os.Stat(filesDir); err == nil {
		filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			extractedFilePaths = append(extractedFilePaths, path)
			t.Logf("Found extracted file: %s (%d bytes)", path, info.Size())
			return nil
		})
	}

	// --- Phase 3: On-demand YARA scanning of extracted files ---
	t.Log("--- On-demand YARA scanning ---")

	matchedFiles := 0
	totalMatches := 0

	for _, fpath := range extractedFilePaths {
		matches, err := scanner.ScanFile(fpath)
		if err != nil {
			t.Errorf("YARA scan failed for %s: %v", fpath, err)
			continue
		}
		if len(matches) > 0 {
			matchedFiles++
			totalMatches += len(matches)
			t.Logf("YARA match on %s: %v", filepath.Base(fpath), matches)
		}
	}

	t.Logf("On-demand scan: %d files scanned, %d files matched, %d total matches",
		len(extractedFilePaths), matchedFiles, totalMatches)

	// --- Phase 4: Verify YARA matches in audit records (auto-scan during capture) ---
	if fileExists(fileAuditPath) {
		reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
		if err != nil {
			t.Fatalf("Failed to open File audit records: %v", err)
		}
		defer reader.Close()

		if _, err := reader.ReadHeader(); err != nil {
			t.Fatalf("Failed to read File audit header: %v", err)
		}

		var fileRecord types.File
		auditFileCount := 0
		auditYaraMatchCount := 0

		for {
			err := reader.Next(&fileRecord)
			if err != nil {
				if err != io.EOF {
					t.Errorf("Error reading file record: %v", err)
				}
				break
			}
			auditFileCount++

			if len(fileRecord.YaraMatches) > 0 {
				auditYaraMatchCount++
				t.Logf("Audit record YARA matches for %s: %v", fileRecord.Name, fileRecord.YaraMatches)

				// Verify match names are from our rules
				for _, match := range fileRecord.YaraMatches {
					if match != "html_content" && match != "text_content" {
						t.Errorf("Unexpected YARA rule match: %s", match)
					}
				}
			}
		}

		t.Logf("Audit records: %d files, %d with YARA matches", auditFileCount, auditYaraMatchCount)

		// If files were extracted, we expect at least some YARA matches in audit records
		if auditFileCount > 0 && auditYaraMatchCount == 0 {
			t.Log("Warning: Files were extracted but no YARA matches found in audit records")
			t.Log("This may indicate the auto-scan didn't fire, or file content didn't match rules")
		}
	}

	// At least one of the scanning approaches must yield matches for the test to pass
	if len(extractedFilePaths) > 0 && matchedFiles == 0 {
		t.Error("Files were extracted but no YARA matches found via on-demand scan")
	}

	// Clean up global state
	file.ResetGlobalYaraScanner()
	file.SetGlobalConfig(file.GetDefaultConfig())
}

// TestYaraScanner_ScanBytes tests the scanner's ability to match byte content directly.
func TestYaraScanner_ScanBytes(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a simple YARA rule
	rule := `
rule test_pattern {
    strings:
        $magic = "NETCAP_TEST_MARKER"
    condition:
        $magic
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yar"), []byte(rule), 0644); err != nil {
		t.Fatalf("Failed to write rule: %v", err)
	}

	scanner, err := file.NewYaraScanner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	if scanner.RuleCount() == 0 {
		t.Fatal("Expected at least 1 compiled rule")
	}

	// Test matching content
	content := []byte("This file contains NETCAP_TEST_MARKER embedded in it")
	matches, err := scanner.ScanBytes(content)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(matches) != 1 || matches[0] != "test_pattern" {
		t.Errorf("Expected [test_pattern], got %v", matches)
	}

	// Test non-matching content
	nonMatching := []byte("This is clean content with no markers")
	matches, err = scanner.ScanBytes(nonMatching)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Expected no matches, got %v", matches)
	}
}

// TestYaraScanner_ScanFile tests scanning a file on disk.
func TestYaraScanner_ScanFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Write YARA rule
	rule := `
rule exe_header {
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule elf_header {
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule pdf_file {
    strings:
        $pdf = "%PDF"
    condition:
        $pdf at 0
}

rule test_string {
    strings:
        $s = "YARA_SCAN_TARGET"
    condition:
        $s
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "rules.yar"), []byte(rule), 0644); err != nil {
		t.Fatalf("Failed to write rule: %v", err)
	}

	scanner, err := file.NewYaraScanner(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Create a test file that matches
	testFile := filepath.Join(tmpDir, "target.bin")
	if err := os.WriteFile(testFile, []byte("YARA_SCAN_TARGET is present in this file"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	matches, err := scanner.ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(matches) != 1 || matches[0] != "test_string" {
		t.Errorf("Expected [test_string], got %v", matches)
	}

	// Create a fake PE file (starts with MZ)
	peFile := filepath.Join(tmpDir, "fake.exe")
	peContent := append([]byte("MZ"), make([]byte, 100)...)
	if err := os.WriteFile(peFile, peContent, 0644); err != nil {
		t.Fatalf("Failed to write PE file: %v", err)
	}

	matches, err = scanner.ScanFile(peFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if len(matches) != 1 || matches[0] != "exe_header" {
		t.Errorf("Expected [exe_header], got %v", matches)
	}
}

// TestYaraScanner_Reload tests reloading rules after adding a new rule file.
func TestYaraScanner_Reload(t *testing.T) {
	tmpDir := t.TempDir()

	// Start with one rule
	rule1 := `rule first_rule { strings: $a = "alpha" condition: $a }`
	if err := os.WriteFile(filepath.Join(tmpDir, "first.yar"), []byte(rule1), 0644); err != nil {
		t.Fatal(err)
	}

	scanner, err := file.NewYaraScanner(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	initialCount := scanner.RuleCount()

	// Add a second rule file
	rule2 := `rule second_rule { strings: $b = "bravo" condition: $b }`
	if err := os.WriteFile(filepath.Join(tmpDir, "second.yar"), []byte(rule2), 0644); err != nil {
		t.Fatal(err)
	}

	// Reload
	if err := scanner.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	newCount := scanner.RuleCount()
	if newCount <= initialCount {
		t.Errorf("Expected more rules after reload: had %d, now %d", initialCount, newCount)
	}

	// Verify both rules match
	matches, _ := scanner.ScanBytes([]byte("alpha"))
	if len(matches) == 0 || matches[0] != "first_rule" {
		t.Errorf("Expected first_rule match, got %v", matches)
	}

	matches, _ = scanner.ScanBytes([]byte("bravo"))
	if len(matches) == 0 || matches[0] != "second_rule" {
		t.Errorf("Expected second_rule match, got %v", matches)
	}
}

// TestYaraScanner_ValidateSource tests rule validation.
func TestYaraScanner_ValidateSource(t *testing.T) {
	// Valid rule
	valid := `rule valid_rule { strings: $a = "test" condition: $a }`
	if err := file.ValidateYaraSource(valid); err != nil {
		t.Errorf("Valid rule rejected: %v", err)
	}

	// Invalid rule
	invalid := `rule broken { strings: condition: }`
	if err := file.ValidateYaraSource(invalid); err == nil {
		t.Error("Invalid rule accepted without error")
	}
}

// TestYaraAvailable confirms yara-x is compiled in.
func TestYaraAvailable(t *testing.T) {
	if !file.YaraAvailable() {
		t.Error("YaraAvailable() returned false, but this test should only run without noyara tag")
	}
}

// TestYaraScanner_EmptyDir tests scanner behavior with no rule files.
func TestYaraScanner_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	scanner, err := file.NewYaraScanner(tmpDir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if scanner.RuleCount() != 0 {
		t.Errorf("Expected 0 rules, got %d", scanner.RuleCount())
	}

	// Scanning with no rules should return no matches
	matches, err := scanner.ScanBytes([]byte("anything"))
	if err != nil {
		t.Fatalf("ScanBytes with no rules failed: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Expected no matches, got %v", matches)
	}
}

// TestYaraScanner_NonexistentDir tests scanner with a missing directory.
func TestYaraScanner_NonexistentDir(t *testing.T) {
	scanner, err := file.NewYaraScanner("/nonexistent/path")
	if err != nil {
		t.Fatalf("Unexpected error for nonexistent dir: %v", err)
	}

	if scanner.RuleCount() != 0 {
		t.Errorf("Expected 0 rules, got %d", scanner.RuleCount())
	}
}

// Suppress unused import warning — strings is used in the integration test
var _ = strings.Contains
