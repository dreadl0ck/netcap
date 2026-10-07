package protocoltest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ReadDirectionalInput enforces adjacent Netcap loss metadata when reading its artifacts.
func ReadDirectionalInput(path string) ([]byte, error) {
	data, err := boundedFile(path, 16<<20)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	if name != "client.bin" && name != "server.bin" {
		return data, nil
	}
	manifestPath := filepath.Join(filepath.Dir(path), "manifest.json")
	metadata, err := boundedFile(manifestPath, 16<<20)
	if os.IsNotExist(err) {
		return data, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Version  int    `json:"version"`
		Status   string `json:"status"`
		Protocol string `json:"protocol"`
		Client   struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"client"`
		Server struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"server"`
		Spans []struct {
			Missing  int  `json:"missingBytes"`
			Datagram bool `json:"datagram"`
		} `json:"spans"`
	}
	if err := json.Unmarshal(metadata, &manifest); err != nil {
		return nil, err
	}
	if manifest.Version != 1 || manifest.Status != "no-reported-gap" || manifest.Protocol != "TCP" {
		return nil, fmt.Errorf("directional input is gapped, datagram-oriented or has unsupported provenance")
	}
	for _, span := range manifest.Spans {
		if span.Missing != 0 || span.Datagram {
			return nil, fmt.Errorf("refusing to parse across recorded stream gaps or datagram boundaries")
		}
	}
	file := manifest.Client
	if name == "server.bin" {
		file = manifest.Server
	}
	digest := sha256.Sum256(data)
	if file.Name != name || file.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("directional input hash does not match manifest")
	}
	return data, nil
}
