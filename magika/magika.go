//go:build !nomagika

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

// Package magika provides AI-based file type classification using the Google Magika Rust CLI.
// The Rust CLI is production-ready with the model embedded in the binary,
// unlike the experimental Go library which requires ONNX Runtime and separate model assets.
package magika

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"sync/atomic"

	"github.com/mgutz/ansi"
)

var (
	magikaBinary string
	enabled      atomic.Bool
)

// Result holds the Magika classification result for a file.
type Result struct {
	Label       string
	MimeType    string
	Group       string
	Description string
	IsText      bool
	Score       float64
}

// magikaJSONOutput represents the JSON output from the magika CLI.
type magikaJSONOutput struct {
	Path   string `json:"path"`
	Result struct {
		Status string `json:"status"`
		Value  struct {
			DL struct {
				Label       string `json:"label"`
				MimeType    string `json:"mime_type"`
				Group       string `json:"group"`
				Description string `json:"description"`
				IsText      bool   `json:"is_text"`
			} `json:"dl"`
			Output struct {
				Label       string `json:"label"`
				MimeType    string `json:"mime_type"`
				Group       string `json:"group"`
				Description string `json:"description"`
				IsText      bool   `json:"is_text"`
			} `json:"output"`
			Score float64 `json:"score"`
		} `json:"value"`
	} `json:"result"`
}

// Init locates the magika CLI binary and verifies it works.
// assetsDir and modelName are ignored (the Rust CLI embeds the model).
func Init(assetsDir, modelName string) {
	log.Println(ansi.Yellow + "[Magika] Init() called" + ansi.Reset)

	// Find the magika binary
	binary, err := exec.LookPath("magika")
	if err != nil {
		log.Printf("[Magika] Error: magika CLI not found in PATH: %v", err)
		log.Println("[Magika] Install via: curl -LsSf https://securityresearch.google/magika/install.sh | sh")
		return
	}

	magikaBinary = binary
	enabled.Store(true)
	log.Printf(ansi.Yellow+"[Magika] Init() done, using binary: %s"+ansi.Reset, magikaBinary)
}

// IsEnabled returns true if the Magika CLI has been found and is ready to use.
func IsEnabled() bool {
	return enabled.Load()
}

// Classify classifies a file at the given path and returns its content type.
func Classify(filePath string) (*Result, error) {
	if !enabled.Load() {
		return nil, nil
	}

	cmd := exec.Command(magikaBinary, "--json", filePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parseJSONOutput(output)
}

// ClassifyBytes classifies file content from a byte slice.
// Writes data to a temp file, runs magika, then removes the temp file.
func ClassifyBytes(data []byte) (*Result, error) {
	if !enabled.Load() {
		return nil, nil
	}

	// Write to temp file (magika CLI needs a file path)
	tmpFile, err := os.CreateTemp("", "magika-classify-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	return Classify(tmpFile.Name())
}

// parseJSONOutput parses the magika CLI JSON output.
func parseJSONOutput(data []byte) (*Result, error) {
	var results []magikaJSONOutput
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, nil
	}

	r := results[0]
	if r.Result.Status != "ok" {
		return nil, nil
	}

	// Use the "output" field (final classification after post-processing)
	return &Result{
		Label:       r.Result.Value.Output.Label,
		MimeType:    r.Result.Value.Output.MimeType,
		Group:       r.Result.Value.Output.Group,
		Description: r.Result.Value.Output.Description,
		IsText:      r.Result.Value.Output.IsText,
		Score:       r.Result.Value.Score,
	}, nil
}

// Destroy cleans up Magika resources.
func Destroy() {
	log.Println(ansi.Red + "[Magika] Destroy() called" + ansi.Reset)
	enabled.Store(false)
}
