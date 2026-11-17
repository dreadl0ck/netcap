package file

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func SaveSpoolEnhanced(conv *core.ConversationInfo, source, name string, bodyErr error, body *BodySpool, encoding []string, host, contentType string, depth int, parentID, direction, protocol string) error {
	if body == nil || body.Size() == 0 || !GetGlobalConfig().FileExtraction.Enabled {
		return nil
	}
	if err := admitArtifact(); err != nil {
		RecordExtractionIssue(err)
		return err
	}
	current := body
	defer func() {
		if current != body {
			RecordArtifactWriteError(current.Close())
		}
	}()
	info := &ContentInfo{Hash: body.content.hashes.SHA256, CompressedSize: body.Size()}
	var hashErr error
	var compressed []string
	policy := GetGlobalConfig().FileExtraction.Advanced
	if len(encoding) > 8 {
		hashErr = fmt.Errorf("encoding stack exceeds 8 layers")
	}
	for _, value := range encoding {
		kind := strings.ToLower(strings.TrimSpace(value))
		if kind == "base64" && !policy.DecodeBase64 || (kind == "gzip" || kind == "deflate" || kind == "br") && !policy.DecodeCompressed {
			hashErr = ErrContentDecodeDisabled
		}
	}
	for index := len(encoding) - 1; index >= 0 && hashErr == nil; index-- {
		kind := strings.ToLower(strings.TrimSpace(encoding[index]))
		if kind == "" || kind == "identity" {
			continue
		}
		decoded, err := decodeSpoolLayer(current, kind)
		if err != nil {
			hashErr = err
			if decoded != nil && decoded.Size() > 0 && len(encoding) == 1 && kind == "gzip" && !errors.Is(err, ErrArtifactLimit) && GetGlobalConfig().FileExtraction.SizeLimits.IncludeMissingBytes {
				prefixErr := SaveSpoolEnhanced(conv, source+" decoded-prefix", "decoded-"+name, errors.Join(bodyErr, err), decoded, nil, host, contentType, depth+1, body.content.hashes.SHA256, direction, protocol)
				RecordExtractionIssue(prefixErr)
			}
			if decoded != nil {
				RecordArtifactWriteError(decoded.Close())
			}
			break
		}
		if current != body {
			RecordArtifactWriteError(current.Close())
		}
		current = decoded
		if kind == "gzip" || kind == "deflate" || kind == "br" {
			compressed = append(compressed, kind)
		}
	}
	if hashErr != nil {
		if current != body {
			RecordArtifactWriteError(current.Close())
			current = body
		}
		info.Hash = body.content.hashes.SHA256
	} else {
		info.Hash = current.content.hashes.SHA256
		info.WasCompressed = len(compressed) > 0
		info.CompressionType = strings.Join(compressed, ",")
	}
	RecordExtractionIssue(hashErr)
	RecordExtractionIssue(bodyErr)
	return savePreparedFile(conv, source, name, bodyErr, info, current.content, hashErr, host, contentType, depth, parentID, direction, protocol)
}

func decodeSpoolLayer(body *BodySpool, kind string) (*BodySpool, error) {
	var lease int64
	switch kind {
	case "gzip", "deflate":
		lease = 1 << 20
	case "base64":
		lease = 8192
	case "br":
		lease = 32 << 20
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", kind)
	}
	if err := reserveBuffer(lease); err != nil {
		return nil, err
	}
	defer releaseBuffer(lease)
	var reader io.Reader
	var closer io.Closer
	switch kind {
	case "gzip":
		r, err := gzip.NewReader(body.Reader())
		if err != nil {
			return nil, err
		}
		reader, closer = r, r
	case "deflate":
		r, err := zlib.NewReader(body.Reader())
		if err == nil {
			reader, closer = r, r
		} else {
			raw := flate.NewReader(body.Reader())
			reader, closer = raw, raw
		}
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, body.Reader())
	case "br":
		reader = brotli.NewReader(body.Reader())
	}
	if closer != nil {
		defer closer.Close()
	}
	return SpoolBody(reader)
}
