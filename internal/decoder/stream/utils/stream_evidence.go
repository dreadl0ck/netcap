package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

type StreamEvidenceSpan struct {
	Direction    string `json:"direction"`
	Offset       int64  `json:"offset,string"`
	Length       int    `json:"length"`
	TimestampNs  string `json:"timestampNs"`
	MissingBytes int    `json:"missingBytes"`
	Datagram     bool   `json:"datagram"`
}

type StreamEvidenceFile struct {
	Name   string `json:"name"`
	Length int64  `json:"length,string"`
	SHA256 string `json:"sha256"`
}

type StreamEvidenceManifest struct {
	Version       int                  `json:"version"`
	Protocol      string               `json:"protocol"`
	ConnectionKey string               `json:"connectionKey"`
	CommunityID   string               `json:"communityId"`
	FirstPacketNs string               `json:"firstPacketNs"`
	Status        string               `json:"status"`
	Client        StreamEvidenceFile   `json:"client"`
	Server        StreamEvidenceFile   `json:"server"`
	Spans         []StreamEvidenceSpan `json:"spans"`
	Limitations   []string             `json:"limitations"`
}

// SaveStreamEvidence preserves payload bytes separately from presentation markup.
// Each call has its own directory, including when a tuple is reused.
func SaveStreamEvidence(out, protocol string, conversation core.DataFragments, ident string, first time.Time, communityID string) (string, error) {
	if protocol != "TCP" && protocol != "UDP" {
		return "", fmt.Errorf("unsupported stream evidence protocol")
	}
	if len(conversation) > 1000000 {
		return "", fmt.Errorf("stream evidence span limit exceeded")
	}
	var size int64
	for _, fragment := range conversation {
		size += int64(len(fragment.Raw()))
		if size > 256<<20 {
			return "", fmt.Errorf("stream evidence byte limit exceeded")
		}
	}
	root := filepath.Join(out, "stream-evidence")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, ".pending-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	client, err := os.OpenFile(filepath.Join(dir, "client.bin"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer client.Close()
	server, err := os.OpenFile(filepath.Join(dir, "server.bin"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer server.Close()
	clientHash, serverHash := sha256.New(), sha256.New()
	writers := []io.Writer{io.MultiWriter(client, clientHash), io.MultiWriter(server, serverHash)}
	manifest := StreamEvidenceManifest{Version: 1, Protocol: protocol, ConnectionKey: ident, CommunityID: communityID, FirstPacketNs: fmt.Sprint(first.UnixNano()), Status: "no-reported-gap",
		Client: StreamEvidenceFile{Name: "client.bin"}, Server: StreamEvidenceFile{Name: "server.bin"}, Spans: []StreamEvidenceSpan{},
		Limitations: []string{"bytes are concatenated observed fragments; gaps are explicit and must not be parsed as contiguous data", "stream completeness and packet provenance require the original capture", "direction follows the reassembler; midstream client role may be uncertain"}}
	offsets := [2]int64{}
	for _, fragment := range conversation {
		direction := 0
		if fragment.Direction() == reassembly.TCPDirServerToClient {
			direction = 1
		}
		if protocol == "UDP" && len(conversation) > 0 {
			if fragment.Transport() == conversation[0].Transport() {
				direction = 0
			} else {
				direction = 1
			}
		}
		name := "client"
		if direction == 1 {
			name = "server"
		}
		capture := fragment.CaptureInfo()
		if fragment.Context() != nil {
			capture = fragment.Context().GetCaptureInfo()
		}
		missing := 0
		if data, ok := fragment.(*core.StreamData); ok {
			missing = data.SkippedBytes
		}
		if missing != 0 {
			manifest.Status = "gapped"
		}
		span := StreamEvidenceSpan{Direction: name, Offset: offsets[direction], Length: len(fragment.Raw()), TimestampNs: fmt.Sprint(capture.Timestamp.UnixNano()), MissingBytes: missing, Datagram: protocol == "UDP"}
		if _, err := writers[direction].Write(fragment.Raw()); err != nil {
			return "", err
		}
		offsets[direction] += int64(span.Length)
		manifest.Spans = append(manifest.Spans, span)
	}
	for _, file := range []*os.File{client, server} {
		if err := file.Sync(); err != nil {
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
	}
	manifest.Client.Length, manifest.Server.Length = offsets[0], offsets[1]
	manifest.Client.SHA256, manifest.Server.SHA256 = hex.EncodeToString(clientHash.Sum(nil)), hex.EncodeToString(serverHash.Sum(nil))
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(filepath.Join(dir, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	target := filepath.Join(root, "stream-"+strings.TrimPrefix(filepath.Base(dir), ".pending-"))
	if err := os.Rename(dir, target); err != nil {
		return "", err
	}
	return target, nil
}
