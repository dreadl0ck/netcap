package utils

import (
	"bytes"
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
	"github.com/gopacket/gopacket"
)

type StreamEvidenceSpan struct {
	Direction      string `json:"direction"`
	Offset         int64  `json:"offset,string"`
	Length         int    `json:"length"`
	TimestampNs    string `json:"timestampNs"`
	MissingBytes   int    `json:"missingBytes"`
	Datagram       bool   `json:"datagram"`
	DiscardedBytes int64  `json:"discardedBytes,omitempty,string"`
	DiscardReason  string `json:"discardReason,omitempty"`
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
	return SaveSourceEvidence(out, protocol, core.SliceSource(conversation), ident, first, communityID)
}

func SaveSourceEvidence(out, protocol string, source core.FragmentSource, ident string, first time.Time, communityID string) (string, error) {
	if protocol != "TCP" && protocol != "UDP" {
		return "", fmt.Errorf("unsupported stream evidence protocol")
	}
	if source.Count() > 1000000 {
		return "", fmt.Errorf("stream evidence span limit exceeded")
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
	var firstSpan []byte
	var spanFile *os.File
	spanPath := filepath.Join(dir, ".spans")
	defer func() {
		if spanFile != nil {
			spanFile.Close()
		}
	}()
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
		Client: StreamEvidenceFile{Name: "client.bin"}, Server: StreamEvidenceFile{Name: "server.bin"},
		Limitations: []string{"bytes are concatenated observed fragments; gaps are explicit and must not be parsed as contiguous data", "stream completeness and packet provenance require the original capture", "direction follows the reassembler; midstream client role may be uncertain"}}
	offsets := [2]int64{}
	hasGap, hasDiscard := false, false
	var visitErr error
	var spans int64
	var firstTransport gopacket.Flow
	err = source.Walk(func(fragment core.DataFragment) bool {
		if spans >= 1000000 {
			visitErr = fmt.Errorf("stream evidence span limit exceeded")
			return false
		}
		raw := fragment.Raw()
		if int64(len(raw)) > 256<<20-offsets[0]-offsets[1] {
			visitErr = fmt.Errorf("stream evidence byte limit exceeded")
			return false
		}
		direction := 0
		if fragment.Direction() == reassembly.TCPDirServerToClient {
			direction = 1
		}
		if protocol == "UDP" {
			transport := fragment.Transport()
			if spans == 0 {
				firstTransport = transport
			}
			if transport == firstTransport {
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
		var discarded int64
		var discardReason string
		if data, ok := fragment.(*core.StreamData); ok {
			missing = data.SkippedBytes
			discarded, discardReason = data.DiscardedBytes, data.DiscardReason
		}
		if missing != 0 {
			hasGap = true
		}
		if discarded > 0 {
			hasDiscard = true
		}
		span := StreamEvidenceSpan{Direction: name, Offset: offsets[direction], Length: len(raw), TimestampNs: fmt.Sprint(capture.Timestamp.UnixNano()), MissingBytes: missing, Datagram: protocol == "UDP"}
		span.DiscardedBytes, span.DiscardReason = discarded, discardReason
		if _, err := writers[direction].Write(raw); err != nil {
			visitErr = err
			return false
		}
		offsets[direction] += int64(span.Length)
		wire, err := json.Marshal(span)
		if err != nil {
			visitErr = err
			return false
		}
		if spans == 0 {
			firstSpan = wire
		} else {
			if spanFile == nil {
				spanFile, err = os.OpenFile(spanPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if err != nil {
					visitErr = err
					return false
				}
			}
			if _, err = spanFile.WriteString(","); err == nil {
				_, err = spanFile.Write(wire)
			}
			if err != nil {
				visitErr = err
				return false
			}
		}
		spans++
		return true
	})
	if err != nil {
		return "", err
	}
	if visitErr != nil {
		return "", visitErr
	}
	if hasDiscard {
		manifest.Status = "locally-truncated"
		manifest.Limitations = append(manifest.Limitations, "local discard spans aggregate omitted reader-copy bytes after their first timestamp; these are not network sequence gaps")
	} else if hasGap {
		manifest.Status = "gapped"
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
	marker := []byte(`"spans":null`)
	position := bytes.Index(data, marker)
	if position < 0 {
		file.Close()
		return "", fmt.Errorf("stream evidence span placeholder missing")
	}
	prefix := append(append([]byte(nil), data[:position]...), []byte(`"spans":[`)...)
	if _, err := file.Write(prefix); err != nil {
		file.Close()
		return "", err
	}
	if _, err = file.Write(firstSpan); err != nil {
		file.Close()
		return "", err
	}
	if spanFile != nil {
		if _, err = spanFile.Seek(0, io.SeekStart); err == nil {
			_, err = io.Copy(file, spanFile)
		}
		if err != nil {
			file.Close()
			return "", err
		}
	}
	if _, err = file.Write(append([]byte("]"), data[position+len(marker):]...)); err != nil {
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
	if spanFile != nil {
		if err = spanFile.Close(); err != nil {
			return "", err
		}
		spanFile = nil
		if err = os.Remove(spanPath); err != nil {
			return "", err
		}
	}
	target := filepath.Join(root, "stream-"+strings.TrimPrefix(filepath.Base(dir), ".pending-"))
	if err := os.Rename(dir, target); err != nil {
		return "", err
	}
	return target, nil
}
