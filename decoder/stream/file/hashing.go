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

package file

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// FileHashes contains multiple hash values for a file
type FileHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

// ComputeHashes calculates MD5, SHA1, and SHA256 hashes for the given data
func ComputeHashes(data []byte) FileHashes {
	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)

	return FileHashes{
		MD5:    hex.EncodeToString(md5Sum[:]),
		SHA1:   hex.EncodeToString(sha1Sum[:]),
		SHA256: hex.EncodeToString(sha256Sum[:]),
	}
}

// StreamingHashWriter computes multiple hashes while writing to a file
// This avoids having to re-read the file contents after writing
type StreamingHashWriter struct {
	file   *os.File
	md5    hash.Hash
	sha1   hash.Hash
	sha256 hash.Hash
}

// NewStreamingHashWriter creates a new streaming hash writer
func NewStreamingHashWriter(file *os.File) *StreamingHashWriter {
	return &StreamingHashWriter{
		file:   file,
		md5:    md5.New(),
		sha1:   sha1.New(),
		sha256: sha256.New(),
	}
}

// Write implements io.Writer and computes hashes while writing
func (w *StreamingHashWriter) Write(p []byte) (n int, err error) {
	// Write to all hash writers
	w.md5.Write(p)
	w.sha1.Write(p)
	w.sha256.Write(p)

	// Write to the actual file
	return w.file.Write(p)
}

// GetHashes returns the computed hashes
func (w *StreamingHashWriter) GetHashes() FileHashes {
	return FileHashes{
		MD5:    hex.EncodeToString(w.md5.Sum(nil)),
		SHA1:   hex.EncodeToString(w.sha1.Sum(nil)),
		SHA256: hex.EncodeToString(w.sha256.Sum(nil)),
	}
}

// Close closes the underlying file
func (w *StreamingHashWriter) Close() error {
	return w.file.Close()
}

// ComputeFileHashes computes hashes for an existing file on disk
func ComputeFileHashes(filepath string) (FileHashes, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return FileHashes{}, err
	}
	defer f.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	// Create a multi-writer to compute all hashes in one pass
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	if _, err := io.Copy(multiWriter, f); err != nil {
		return FileHashes{}, err
	}

	return FileHashes{
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

