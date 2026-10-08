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
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"

	gzip "github.com/klauspost/pgzip"
	"go.uber.org/zap"
)

// fileDeduplicationCache stores SHA256 hashes of already extracted files
// to prevent saving duplicate files with identical content.
type fileDeduplicationCache struct {
	mu         sync.RWMutex
	hashToPath map[string]string // SHA256 hash -> file path on disk
	stats      dedupStats
}

// dedupStats tracks deduplication statistics
type dedupStats struct {
	TotalFiles     int64 // Total files processed
	UniqueFiles    int64 // Unique files saved to disk
	DuplicateFiles int64 // Duplicate files skipped
	BytesSaved     int64 // Bytes saved by not writing duplicates
}

// global deduplication cache
var (
	dedupCache     *fileDeduplicationCache
	dedupCacheOnce sync.Once
)

// initDedupCache initializes the deduplication cache
func initDedupCache() {
	dedupCacheOnce.Do(func() {
		dedupCache = &fileDeduplicationCache{
			hashToPath: make(map[string]string),
		}
	})
}

// GetDedupCache returns the global deduplication cache
func GetDedupCache() *fileDeduplicationCache {
	initDedupCache()
	return dedupCache
}

// ResetDedupCache resets the deduplication cache (useful for testing or new capture sessions)
func ResetDedupCache() {
	initDedupCache()
	dedupCache.mu.Lock()
	defer dedupCache.mu.Unlock()
	dedupCache.hashToPath = make(map[string]string)
	dedupCache.stats = dedupStats{}
}

// GetDedupStats returns the current deduplication statistics
func GetDedupStats() dedupStats {
	initDedupCache()
	dedupCache.mu.RLock()
	defer dedupCache.mu.RUnlock()
	return dedupCache.stats
}

// CheckAndRegister checks if a file with this hash already exists.
// If it does, returns (existingPath, true). Otherwise registers the new path and returns ("", false).
func (c *fileDeduplicationCache) CheckAndRegister(hash string, newPath string, fileSize int64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalFiles++

	if existingPath, exists := c.hashToPath[hash]; exists {
		c.stats.DuplicateFiles++
		c.stats.BytesSaved += fileSize
		return existingPath, true
	}

	c.hashToPath[hash] = newPath
	c.stats.UniqueFiles++
	return "", false
}

// Lookup checks if a hash exists in the cache without modifying it
func (c *fileDeduplicationCache) Lookup(hash string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	path, exists := c.hashToPath[hash]
	return path, exists
}

// ContentInfo contains information about decoded content
type ContentInfo struct {
	Hash            string // SHA256 hash of the decoded content
	DecodedContent  []byte // Decompressed content
	WasCompressed   bool   // Whether the content was compressed
	CompressionType string // Compression algorithm (gzip, deflate, or empty)
	CompressedSize  int64  // Original compressed size
}

// ComputeContentHash computes SHA256 hash of the content, handling all encoding types.
// This function decodes gzip/deflate/base64 content before hashing to ensure we hash the actual content.
// It also returns compression information for audit records.
func ComputeContentHash(body []byte, encoding []string) (*ContentInfo, error) {
	limit := GetMaxFileSize()
	if limit <= 0 {
		limit = 100 << 20
	}
	return ComputeContentHashWithLimit(body, encoding, limit)
}

func ComputeContentHashWithLimit(body []byte, encoding []string, limit int64) (*ContentInfo, error) {
	info := &ContentInfo{
		CompressedSize: int64(len(body)),
	}
	fallback := func(err error) (*ContentInfo, error) {
		hash := sha256.Sum256(body)
		return &ContentInfo{Hash: hex.EncodeToString(hash[:]), DecodedContent: body, CompressedSize: int64(len(body))}, err
	}
	if limit <= 0 || limit == math.MaxInt64 || len(encoding) > 8 {
		return fallback(fmt.Errorf("invalid decoded-content limit or encoding stack exceeds 8 layers"))
	}
	current := body
	var compressed []string
	// Content-Encoding lists application order; decoding reverses it.
	for i := len(encoding) - 1; i >= 0; i-- {
		enc := strings.ToLower(strings.TrimSpace(encoding[i]))
		var reader io.Reader
		var closer io.Closer
		switch enc {
		case "", "identity":
			continue
		case "gzip":
			r, err := gzip.NewReader(bytes.NewReader(current))
			if err != nil {
				return fallback(fmt.Errorf("decode gzip: %w", err))
			}
			reader, closer = r, r
		case "deflate":
			r, err := zlib.NewReader(bytes.NewReader(current))
			if err == nil {
				reader, closer = r, r
			} else {
				raw := flate.NewReader(bytes.NewReader(current))
				reader, closer = raw, raw
			}
		case "base64":
			reader = base64.NewDecoder(base64.StdEncoding, bytes.NewReader(current))
		default:
			return fallback(fmt.Errorf("unsupported content encoding %q", enc))
		}
		decoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
		if closer != nil {
			closeErr := closer.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			return fallback(fmt.Errorf("decode %s: %w", enc, err))
		}
		if int64(len(decoded)) > limit {
			return fallback(fmt.Errorf("decoded-content limit exceeded: %d", limit))
		}
		if enc == "gzip" || enc == "deflate" {
			compressed = append(compressed, enc)
		}
		current = decoded
	}
	if int64(len(current)) > limit {
		return fallback(fmt.Errorf("decoded-content limit exceeded: %d", limit))
	}
	info.DecodedContent = current
	info.WasCompressed = len(compressed) > 0
	info.CompressionType = strings.Join(compressed, ",")
	hash := sha256.Sum256(current)
	info.Hash = hex.EncodeToString(hash[:])
	return info, nil
}

// LogDedupStats logs the current deduplication statistics
func LogDedupStats(logger *zap.Logger) {
	stats := GetDedupStats()
	if stats.TotalFiles > 0 {
		logger.Info("File deduplication statistics",
			zap.Int64("totalFiles", stats.TotalFiles),
			zap.Int64("uniqueFiles", stats.UniqueFiles),
			zap.Int64("duplicateFiles", stats.DuplicateFiles),
			zap.Int64("bytesSaved", stats.BytesSaved),
			zap.Float64("deduplicationRatio", float64(stats.DuplicateFiles)/float64(stats.TotalFiles)*100),
		)
	}
}
