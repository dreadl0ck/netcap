package protocoltest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"
)

type TLSCaptureResult struct {
	Node0Text    string            `json:"node0Text,omitempty"`
	Node1Text    string            `json:"node1Text,omitempty"`
	HTTP2        []TLSHTTP2Message `json:"http2,omitempty"`
	DecodeErrors []string          `json:"decodeErrors,omitempty"`
	Version      int               `json:"version"`
	InputSHA256  string            `json:"inputSHA256"`
	KeyLogSHA256 string            `json:"keyLogSHA256"`
	ToolVersion  string            `json:"toolVersion"`
	Stream       int               `json:"stream"`
	Client       []byte            `json:"node0Bytes"`
	Server       []byte            `json:"node1Bytes"`
	ClientSHA256 string            `json:"node0SHA256"`
	ServerSHA256 string            `json:"node1SHA256"`
	Nodes        []string          `json:"nodes"`
	Limitations  []string          `json:"limitations"`
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		return 0, fmt.Errorf("TLS adapter output limit exceeded")
	}
	return b.Buffer.Write(data)
}

// AnalyzeTLSCapture delegates cryptographic dissection to the installed tshark.
// Node direction follows tshark's reported endpoints; no client-role inference is made.
func AnalyzeTLSCapture(ctx context.Context, input, keyLog string, stream int) (TLSCaptureResult, error) {
	result := TLSCaptureResult{Version: 1, Stream: stream, Nodes: []string{}, Limitations: []string{"external tshark adapter: plaintext depends on available secrets, supported ciphers and complete records", "node ordering is reported by tshark, not asserted to be client/server", "reassembled plaintext alone does not establish capture completeness or endpoint effects"}}
	if stream < 0 {
		return result, fmt.Errorf("stream must be nonnegative")
	}
	tool, err := exec.LookPath("tshark")
	if err != nil {
		return result, fmt.Errorf("TLS analysis requires installed tshark: %w", err)
	}
	inputData, err := boundedFile(input, 256<<20)
	if err != nil {
		return result, err
	}
	inputHash := sha256.Sum256(inputData)
	result.InputSHA256 = hex.EncodeToString(inputHash[:])
	secrets, err := boundedFile(keyLog, 4<<20)
	if err != nil {
		return result, err
	}
	if len(bytes.TrimSpace(secrets)) == 0 {
		return result, fmt.Errorf("TLS key log is empty")
	}
	keyHash := sha256.Sum256(secrets)
	result.KeyLogSHA256 = hex.EncodeToString(keyHash[:])
	version := exec.CommandContext(ctx, tool, "--version")
	versionOut := &cappedBuffer{limit: 65536}
	version.Stdout, version.Stderr = versionOut, versionOut
	if err := version.Run(); err != nil {
		return result, err
	}
	result.ToolVersion = strings.SplitN(versionOut.String(), "\n", 2)[0]
	command := exec.CommandContext(ctx, tool, "-n", "-r", input, "-o", "tls.keylog_file:"+keyLog, "-q", "-z", "follow,tls,raw,"+strconv.Itoa(stream))
	output, stderr := &cappedBuffer{limit: 32 << 20}, &cappedBuffer{limit: 65536}
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		return result, fmt.Errorf("TLS dissection failed: %w", err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Node ") {
			result.Nodes = append(result.Nodes, trimmed)
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "=") || strings.HasPrefix(trimmed, "Follow:") || strings.HasPrefix(trimmed, "Filter:") {
			continue
		}
		data, err := hex.DecodeString(trimmed)
		if err != nil {
			return result, fmt.Errorf("unrecognized tshark TLS transcript format")
		}
		if strings.HasPrefix(line, "\t") {
			result.Server = append(result.Server, data...)
		} else {
			result.Client = append(result.Client, data...)
		}
	}
	if len(result.Nodes) != 2 || len(result.Client)+len(result.Server) == 0 {
		return result, fmt.Errorf("no decrypted application bytes: secrets, stream selection or capture coverage may be insufficient")
	}
	clientHash, serverHash := sha256.Sum256(result.Client), sha256.Sum256(result.Server)
	result.ClientSHA256, result.ServerSHA256 = hex.EncodeToString(clientHash[:]), hex.EncodeToString(serverHash[:])
	if utf8.Valid(result.Client) {
		result.Node0Text = string(result.Client)
	}
	if utf8.Valid(result.Server) {
		result.Node1Text = string(result.Server)
	}
	result.HTTP2, result.DecodeErrors = decodeTLSHTTP2(result.Client, result.Server)
	check, err := boundedFile(input, 256<<20)
	if err != nil {
		return result, err
	}
	if sha256.Sum256(check) != inputHash {
		return result, fmt.Errorf("capture changed during TLS dissection")
	}
	check, err = boundedFile(keyLog, 4<<20)
	if err != nil {
		return result, err
	}
	if sha256.Sum256(check) != keyHash {
		return result, fmt.Errorf("TLS key log changed during dissection")
	}
	return result, ctx.Err()
}

var _ io.Writer = (*cappedBuffer)(nil)
