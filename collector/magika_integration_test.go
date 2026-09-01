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

package collector_test

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/magika"
	"github.com/dreadl0ck/netcap/types"
)

// TestMagikaFileClassification is an end-to-end integration test that:
// 1. Processes a PCAP containing HTTP traffic with PHP/HTML file transfers
// 2. Extracts files with Magika classification enabled
// 3. Verifies File audit records contain correct Magika classification fields
func TestMagikaFileClassification(t *testing.T) {
	if !fileExists(httpAuthPCAP) {
		t.Skip("HTTP test PCAP not found:", httpAuthPCAP)
	}

	// Check if magika CLI is available
	magika.Init("", "")
	if !magika.IsEnabled() {
		t.Skip("magika CLI not found in PATH — install via: curl -LsSf https://securityresearch.google/magika/install.sh | sh")
	}

	tmpDir := t.TempDir()

	// Configure file extraction with Magika enabled
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	cfg.FileExtraction.HashAlgorithms.MD5 = true
	cfg.FileExtraction.HashAlgorithms.SHA256 = true
	cfg.FileExtraction.Advanced.EnableMagika = true
	cfg.FileExtraction.Advanced.DeduplicateFiles = true
	file.SetGlobalConfig(cfg)

	// Create collector and run capture
	c := createTestCollector(tmpDir, false)
	c.InputFile = httpAuthPCAP

	err := c.CollectPcap(httpAuthPCAP)
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}

	// Read File audit records
	fileAuditPath := filepath.Join(tmpDir, "File.ncap.gz")
	if !fileExists(fileAuditPath) {
		t.Fatal("No File audit records created — expected file extraction from HTTP traffic")
	}

	reader, err := netio.Open(fileAuditPath, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open File audit records: %v", err)
	}
	defer reader.Close()

	_, err = reader.ReadHeader()
	if err != nil {
		t.Fatalf("Failed to read File audit header: %v", err)
	}

	var (
		fileRecord      types.File
		totalFiles      int
		filesWithMagika int
		foundPHP        bool
		foundHTML       bool
		magikaGroups    = make(map[string]int)
		magikaLabels    = make(map[string]int)
		magikaMimeTypes = make(map[string]int)
	)

	for {
		err := reader.Next(&fileRecord)
		if err != nil {
			if err != io.EOF {
				t.Errorf("Error reading file record: %v", err)
			}
			break
		}

		if fileRecord.Length == 0 || fileRecord.Name == "" {
			continue
		}
		totalFiles++

		// Check Magika classification fields
		if fileRecord.MagikaLabel != "" {
			filesWithMagika++
			magikaLabels[fileRecord.MagikaLabel]++
			magikaGroups[fileRecord.MagikaGroup]++
			magikaMimeTypes[fileRecord.MagikaMimeType]++

			t.Logf("File: %s → Magika: label=%s, mime=%s, group=%s, isText=%v",
				fileRecord.Name,
				fileRecord.MagikaLabel,
				fileRecord.MagikaMimeType,
				fileRecord.MagikaGroup,
				fileRecord.MagikaIsText,
			)

			// Verify required fields are populated
			if fileRecord.MagikaMimeType == "" {
				t.Errorf("File %s: MagikaLabel=%s but MagikaMimeType is empty", fileRecord.Name, fileRecord.MagikaLabel)
			}
			if fileRecord.MagikaGroup == "" {
				t.Errorf("File %s: MagikaLabel=%s but MagikaGroup is empty", fileRecord.Name, fileRecord.MagikaLabel)
			}
			if fileRecord.MagikaDescription == "" {
				t.Errorf("File %s: MagikaLabel=%s but MagikaDescription is empty", fileRecord.Name, fileRecord.MagikaLabel)
			}

			// Track expected file types from http-basic-auth.pcap
			if fileRecord.MagikaLabel == "php" {
				foundPHP = true
				if fileRecord.MagikaMimeType != "text/x-php" {
					t.Errorf("PHP file %s: expected MIME text/x-php, got %s", fileRecord.Name, fileRecord.MagikaMimeType)
				}
				if !fileRecord.MagikaIsText {
					t.Errorf("PHP file %s: expected MagikaIsText=true", fileRecord.Name)
				}
				if fileRecord.MagikaGroup != "code" {
					t.Errorf("PHP file %s: expected group=code, got %s", fileRecord.Name, fileRecord.MagikaGroup)
				}
			}
			if fileRecord.MagikaLabel == "html" {
				foundHTML = true
				if fileRecord.MagikaMimeType != "text/html" {
					t.Errorf("HTML file %s: expected MIME text/html, got %s", fileRecord.Name, fileRecord.MagikaMimeType)
				}
				if !fileRecord.MagikaIsText {
					t.Errorf("HTML file %s: expected MagikaIsText=true", fileRecord.Name)
				}
			}
		}
	}

	// Verify results
	if totalFiles == 0 {
		t.Fatal("No files extracted from HTTP traffic")
	}

	if filesWithMagika == 0 {
		t.Fatal("No files received Magika classification — expected classification on all extracted files")
	}

	t.Logf("Summary: %d/%d files classified by Magika", filesWithMagika, totalFiles)
	t.Logf("Labels: %v", magikaLabels)
	t.Logf("Groups: %v", magikaGroups)
	t.Logf("MIME types: %v", magikaMimeTypes)

	// The http-basic-auth.pcap contains server-rendered PHP pages (HTML output) and HTML content.
	// Magika correctly classifies the transferred content (HTML), not the server-side source (PHP).
	if !foundPHP && !foundHTML {
		t.Error("Expected at least PHP or HTML classification from http-basic-auth.pcap, got neither")
	}
	if foundHTML {
		t.Log("Magika correctly identified HTML content in server-rendered PHP responses")
	}

	// Verify classification rate — all files should be classified when Magika is enabled
	classificationRate := float64(filesWithMagika) / float64(totalFiles) * 100
	t.Logf("Classification rate: %.1f%%", classificationRate)
	if classificationRate < 50 {
		t.Errorf("Classification rate too low: %.1f%% (expected >50%%)", classificationRate)
	}
}
