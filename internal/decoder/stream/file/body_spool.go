package file

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
)

var artifactScratch struct {
	sync.Mutex
	used int64
}

// Includes the read buffer, token overlap, and bounded text-analysis copies.
const artifactScanMemory int64 = 256 << 10

func reserveArtifactScratch(n int64) error {
	limit := GetGlobalConfig().FileExtraction.SizeLimits.MaxScratchBytes
	if limit == 0 {
		limit = 1 << 30
	}
	artifactScratch.Lock()
	defer artifactScratch.Unlock()
	if n > limit-artifactScratch.used {
		return fmt.Errorf("%w: scratch storage", ErrArtifactLimit)
	}
	artifactScratch.used += n
	return nil
}
func releaseArtifactScratch(n int64) {
	artifactScratch.Lock()
	defer artifactScratch.Unlock()
	artifactScratch.used -= n
	if artifactScratch.used < 0 {
		panic("artifact scratch accounting underflow")
	}
}

type BodySpool struct {
	content *artifactData
	credit  int64
	closed  bool
}

func (b *BodySpool) Size() int64       { return b.content.Size() }
func (b *BodySpool) Reader() io.Reader { return b.content.Reader() }
func (b *BodySpool) Prefix() []byte    { return b.content.prefix }
func (b *BodySpool) Close() error {
	if b == nil || b.closed {
		return nil
	}
	name := b.content.file.Name()
	err := b.content.file.Close()
	removeErr := os.Remove(name)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		releaseArtifactScratch(b.credit)
		b.credit = 0
		b.closed = true
	}
	return errors.Join(err, removeErr)
}

func SpoolBody(reader io.Reader) (result *BodySpool, resultErr error) {
	if err := reserveBuffer(artifactScanMemory); err != nil {
		return nil, err
	}
	defer releaseBuffer(artifactScanMemory)
	root := filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch")
	if err := os.MkdirAll(root, 0700); err != nil {
		RecordArtifactWriteError(err)
		return nil, err
	}
	file, err := os.CreateTemp(root, "body-")
	if err != nil {
		RecordArtifactWriteError(err)
		return nil, err
	}
	result = &BodySpool{content: &artifactData{file: file}}
	returned := false
	defer func() {
		if !returned {
			_ = result.Close()
		}
	}()
	md5Hash, sha1Hash, sha256Hash := md5.New(), sha1.New(), sha256.New()
	hashes := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)
	var facts artifactFacts
	buffer := make([]byte, 32768)
	limit := GetMaxFileSize()
	if limit <= 0 || limit > 100<<20 {
		limit = 100 << 20
	}
	empty := 0
	for {
		n, readErr := reader.Read(buffer[:min(int64(len(buffer)), limit-result.content.size+1)])
		if n > 0 {
			empty = 0
			if int64(n) > limit-result.content.size {
				n = int(limit - result.content.size)
				readErr = fmt.Errorf("%w: per-file %d", ErrArtifactLimit, limit)
			}
			if err := reserveArtifactScratch(int64(n)); err != nil {
				resultErr = err
				break
			}
			written, writeErr := file.Write(buffer[:n])
			result.credit += int64(written)
			releaseArtifactScratch(int64(n - written))
			if written > 0 {
				_, _ = hashes.Write(buffer[:written])
				facts.feed(buffer[:written])
				result.content.size += int64(written)
			}
			if writeErr == nil && written != n {
				writeErr = io.ErrShortWrite
			}
			if writeErr != nil {
				RecordArtifactWriteError(writeErr)
				resultErr = writeErr
				break
			}
		} else if readErr == nil {
			empty++
		}
		if readErr != nil {
			if readErr != io.EOF {
				resultErr = readErr
			}
			break
		}
		if empty >= 100 {
			resultErr = io.ErrNoProgress
			break
		}
	}
	if err := file.Sync(); err != nil {
		RecordArtifactWriteError(err)
		resultErr = errors.Join(resultErr, err)
	}
	result.content.hashes = FileHashes{MD5: hex.EncodeToString(md5Hash.Sum(nil)), SHA1: hex.EncodeToString(sha1Hash.Sum(nil)), SHA256: hex.EncodeToString(sha256Hash.Sum(nil))}
	result.content.mime, result.content.accurate = facts.mimeType()
	result.content.prefix = facts.prefix
	facts.tail = nil
	result.content.facts = &facts
	returned = true
	return result, resultErr
}
