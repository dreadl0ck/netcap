/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package webui

import (
	"io/fs"
	"path/filepath"
	"testing"
)

// TestEmbeddedEchartsFiles verifies that required echarts files are embedded
func TestEmbeddedEchartsFiles(t *testing.T) {
	// Required files for 3D charts
	requiredFiles := []string{
		"static/echarts/echarts.min.js",
		"static/echarts/echarts@4.min.js",
		"static/echarts/echarts-gl.min.js",
		"static/echarts/themes/macarons.js",
	}

	fsSub, err := fs.Sub(EmbeddedAssets, "frontend/out")
	if err != nil {
		t.Fatalf("Failed to access embedded assets: %v", err)
	}

	t.Log("Checking embedded echarts files...")

	for _, file := range requiredFiles {
		info, err := fs.Stat(fsSub, file)
		if err != nil {
			t.Errorf("Required file NOT found: %s (error: %v)", file, err)
		} else {
			t.Logf("✓ Found: %s (size: %d bytes)", file, info.Size())
		}
	}

	// List all files in static/echarts
	t.Log("\nAll embedded files in static/echarts:")
	err = fs.WalkDir(fsSub, "static/echarts", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, _ := d.Info()
			t.Logf("  %s (size: %d bytes)", path, info.Size())
		}
		return nil
	})
	if err != nil {
		t.Errorf("Failed to list static/echarts directory: %v", err)
	}
}

// TestEmbedDirective verifies the embed directive is working
func TestEmbedDirective(t *testing.T) {
	entries, err := fs.ReadDir(EmbeddedAssets, ".")
	if err != nil {
		t.Fatalf("Failed to read embedded root: %v", err)
	}

	t.Log("Root embedded directories:")
	for _, entry := range entries {
		t.Logf("  - %s (isDir: %v)", entry.Name(), entry.IsDir())
	}

	// Check if frontend/out exists
	fsSub, err := fs.Sub(EmbeddedAssets, "frontend/out")
	if err != nil {
		t.Fatalf("frontend/out not embedded: %v", err)
	}

	// Check if static directory exists
	entries, err = fs.ReadDir(fsSub, "static")
	if err != nil {
		t.Fatalf("static directory not found in embedded assets: %v", err)
	}

	t.Log("\nDirectories in frontend/out/static:")
	for _, entry := range entries {
		if entry.IsDir() {
			t.Logf("  - %s/", entry.Name())

			// If it's echarts, list its contents
			if entry.Name() == "echarts" {
				subEntries, subErr := fs.ReadDir(fsSub, filepath.Join("static", entry.Name()))
				if subErr == nil {
					for _, sub := range subEntries {
						if sub.IsDir() {
							t.Logf("    - %s/", sub.Name())
						} else {
							t.Logf("    - %s", sub.Name())
						}
					}
				}
			}
		}
	}
}
