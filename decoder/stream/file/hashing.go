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
