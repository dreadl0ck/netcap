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

package collector

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/utils"
)

func TestStreamDirectionHTTP(t *testing.T) {
	// Setup temp output dir
	outDir, err := os.MkdirTemp("", "netcap_stream_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)

	// Config
	cfg := Config{
		Workers:               4, // Use multiple workers to verify sharding fixes directionality
		PacketBufferSize:      100,
		DPI:                   false,
		NoSignalHandling:      true,
		NoPrompt:              true,
		ReassembleConnections: true,
		DecoderConfig: &config.Config{
			Out:                     outDir,
			Quiet:                   true,
			SaveConns:               true,
			IncludePayloads:         false,
			Proto:                   true, // Required
			AllowMissingInit:        true,
			WriteIncomplete:         true,
			IgnoreFSMerr:            true,
			StreamDecoderBufSize:    100,
			StreamBufferSize:        100,
			NumStreamWorkers:        4,
			IgnoreDecoderInitErrors: true,
			IncludeDecoders:         "Ethernet,IPv4,TCP,HTTP,Connection",
			// Use defaults for others
			BannerSize: 256,
		},
		BaseLayer:     utils.GetBaseLayer("ethernet"),
		DecodeOptions: utils.GetDecodeOptions("default"),
	}

	c := New(cfg)
	inputFile := "testdata/http.pcap"

	// collector/testdata is gitignored, so this fixture is absent on a clean
	// checkout and in CI. Skip rather than fail on a missing input.
	if _, err := os.Stat(inputFile); err != nil {
		t.Skipf("pcap fixture %s not available (%v)", inputFile, err)
	}

	// Run
	err = c.CollectPcap(inputFile)
	if err != nil {
		t.Fatal(err)
	}

	// Check for conversation file
	// Find any .bin file in the output directory that looks like HTTP (TCP)
	var foundFile string
	err = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".bin") {
			// Check if it's TCP
			if strings.Contains(path, "/tcp/") {
				// Read content to see if it's the HTTP one
				content, _ := os.ReadFile(path)
				if strings.Contains(string(content), "GET") {
					foundFile = path
					return io.EOF // Stop search
				}
			}
		}
		return nil
	})

	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if foundFile == "" {
		t.Fatal("No HTTP conversation file found in", outDir)
	}

	t.Log("Found conversation file:", foundFile)

	// Read file content
	content, err := os.ReadFile(foundFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(content)

	// Check for "GET"
	idxGET := strings.Index(s, "GET")
	if idxGET == -1 {
		t.Fatal("GET request not found in conversation")
	}

	paths, err := filepath.Glob(filepath.Join(outDir, "stream-evidence", "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var manifest streamutils.StreamEvidenceManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		client, err := os.ReadFile(filepath.Join(filepath.Dir(path), manifest.Client.Name))
		if err != nil {
			t.Fatal(err)
		}
		server, err := os.ReadFile(filepath.Join(filepath.Dir(path), manifest.Server.Name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(client, []byte("GET")) && bytes.Equal(append(bytes.Clone(client), server...), content) {
			matched = true
		}
	}
	if !matched {
		t.Fatal("raw HTTP conversation differs from directional payload evidence")
	}
}
