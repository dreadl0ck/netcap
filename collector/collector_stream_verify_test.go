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

package collector

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/utils"
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
		ReassembleConnections: true,
		DecoderConfig: &config.Config{
			Out:                   outDir,
			Quiet:                 true,
			SaveConns:             true,
			IncludePayloads:       false,
            Proto:                 true, // Required
			AllowMissingInit:      true,
			WriteIncomplete:       true,
			IgnoreFSMerr:          true,
			StreamDecoderBufSize:  100,
			StreamBufferSize:      100,
			NumStreamWorkers:      4,
            // Exclude DPI-dependent decoders to prevent crash
            ExcludeDecoders:       "DeviceProfile,IPProfile,Connection",
            // Use defaults for others
            BannerSize: 256,
		},
        BaseLayer: utils.GetBaseLayer("ethernet"),
        DecodeOptions: utils.GetDecodeOptions("default"),
	}

	c := New(cfg)
	inputFile := "testdata/http.pcap"

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

    // Check color
    lastColor := getColorBeforeIndex(s, idxGET)
    if lastColor != "red" {
        t.Errorf("GET request should be Red (Client), but found color: %s", lastColor)
    }

    // Check for 200 OK
    idx200 := strings.Index(s, "200 OK")
    if idx200 != -1 {
        lastColorResponse := getColorBeforeIndex(s, idx200)
        if lastColorResponse != "blue" {
             t.Errorf("200 OK response should be Blue (Server), but found color: %s", lastColorResponse)
        }
    } else {
        t.Log("200 OK not found in conversation (maybe partial capture)")
    }
}



func getColorBeforeIndex(s string, idx int) string {
    // Common ANSI codes
    redCodes := []string{"\x1b[0;31m", "\x1b[31m"}
    blueCodes := []string{"\x1b[0;34m", "\x1b[34m"}
    
	for i := idx; i >= 0; i-- {
		if s[i] == 0x1b { // ESC
            sub := s[i:]
            for _, code := range redCodes {
                if strings.HasPrefix(sub, code) {
                    return "red"
                }
            }
            for _, code := range blueCodes {
                if strings.HasPrefix(sub, code) {
                    return "blue"
                }
            }
		}
	}
    return "unknown"
}

