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
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/defaults"
	magikapkg "github.com/dreadl0ck/netcap/magika"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// sanitizeStringFields sanitizes string fields to ensure valid UTF-8 for protobuf encoding.
func sanitizeStringFields(source, host, contentType, cTypeDetected, flowDirection string) (string, string, string, string, string) {
	return utils.SanitizeUTF8(source),
		utils.SanitizeUTF8(host),
		utils.SanitizeUTF8(contentType),
		utils.SanitizeUTF8(cTypeDetected),
		utils.SanitizeUTF8(flowDirection)
}

var saveFileLog = zap.NewNop()

// Protect dedup lookup through publication, and filename allocation across contents.
var saveFileMu sync.Mutex

// SetSaveFileLogger sets the logger for file saving operations
func SetSaveFileLogger(logger *zap.Logger) {
	saveFileLog = logger
}

// SaveFileEnhanced is an enhanced version of SaveFile with support for:
// - Multiple hash algorithms (MD5, SHA1, SHA256)
// - Better content type detection
// - Depth tracking for nested files
// - Parent file tracking
// - Flow direction tracking
// - Protocol tracking (HTTP, FTP, SMB, SMTP, IRC, etc.)
// - Configuration-based filtering and settings
func SaveFileEnhanced(
	conv *core.ConversationInfo,
	source, name string,
	err error,
	body []byte,
	encoding []string,
	host string,
	contentType string,
	depth int,
	parentFileID string,
	flowDirection string,
	protocol string,
) error {
	saveFileLog.Info("SaveFileEnhanced",
		zap.String("source", source),
		zap.String("name", name),
		zap.Error(err),
		zap.Int("bodyLength", len(body)),
		zap.Strings("encoding", encoding),
		zap.String("host", host),
		zap.Int("depth", depth),
		zap.String("flowDirection", flowDirection),
		zap.String("protocol", protocol),
	)

	// Check if file extraction is enabled globally
	cfg := GetGlobalConfig()
	if !cfg.FileExtraction.Enabled {
		return nil
	}

	// Prevent saving zero bytes
	if len(body) == 0 {
		return nil
	}

	// Check size limits
	if cfg.FileExtraction.SizeLimits.MaxFileSize > 0 && int64(len(body)) > cfg.FileExtraction.SizeLimits.MaxFileSize {
		saveFileLog.Info("File exceeds size limit, skipping",
			zap.Int("size", len(body)),
			zap.Int64("limit", cfg.FileExtraction.SizeLimits.MaxFileSize),
		)
		return nil
	}

	if name == "" || name == "/" {
		name = "unknown"
	}

	// Compute content hash BEFORE writing for deduplication
	// This decodes gzip/deflate/base64 content to hash the actual content
	// and tracks compression information for the audit record
	contentInfo, hashErr := ComputeContentHash(body, encoding)
	if hashErr != nil {
		saveFileLog.Error("failed to compute content hash",
			zap.String("ident", conv.Ident),
			zap.Error(hashErr),
		)
		// Continue with original body if hash computation fails
		contentInfo = &ContentInfo{
			Hash:           "",
			DecodedContent: body,
			WasCompressed:  false,
			CompressedSize: int64(len(body)),
		}
	}

	// Log compression info if file was compressed
	if contentInfo.WasCompressed {
		saveFileLog.Info("Decompressed file content",
			zap.String("ident", conv.Ident),
			zap.String("name", name),
			zap.String("compressionType", contentInfo.CompressionType),
			zap.Int64("compressedSize", contentInfo.CompressedSize),
			zap.Int("decompressedSize", len(contentInfo.DecodedContent)),
		)
	}

	// Enhanced content type detection (if enabled) - run on DECOMPRESSED content
	var cTypeDetected string
	var accurate bool

	if cfg.FileExtraction.Advanced.UseMagicDetection {
		// Use decompressed content for accurate magic detection
		cTypeDetected, accurate = DetectContentType(contentInfo.DecodedContent)
	} else {
		cTypeDetected = trimEncoding(decoderconfig.Instance.FileStorage)
	}

	// Use detected type if more accurate than provided
	if accurate && contentType == "" {
		contentType = cTypeDetected
	}

	// Check MIME type filtering
	if !ShouldExtractMimeType(cTypeDetected) {
		saveFileLog.Debug("MIME type filtered, skipping extraction",
			zap.String("mimeType", cTypeDetected),
		)
		return nil
	}

	// Root path based on content type
	root := path.Join(decoderconfig.Instance.Out, decoderconfig.Instance.FileStorage, cTypeDetected)

	// File extension based on detected content type
	ext := ExtensionForContentType(cTypeDetected)

	// File basename
	base := filepath.Clean(name+"-"+path.Base(utils.CleanIdent(conv.Ident))) + ext

	if err != nil {
		base = "incomplete-" + base
	}

	// Determine filename
	fileName := name
	if filepath.Ext(name) == "" {
		fileName = name + ext
	}

	// Create directory structure
	if err := os.MkdirAll(root, defaults.DirectoryPermission); err != nil {
		saveFileLog.Error("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
			zap.Error(err),
		)
	}

	base = path.Join(root, base)

	// Truncate overly long paths
	if len(base) > 250 {
		base = base[:250] + "..."
	}

	if base == decoderconfig.Instance.FileStorage {
		base = path.Join(decoderconfig.Instance.Out, decoderconfig.Instance.FileStorage, "noname")
	}

	// Check for duplicate content using deduplication cache
	saveFileMu.Lock()
	defer saveFileMu.Unlock()

	var target string
	var length int64
	var hashes FileHashes
	var isDuplicate bool

	if cfg.FileExtraction.Advanced.DeduplicateFiles && contentInfo.Hash != "" {
		// Check if we've already saved a file with this content hash (lookup only, don't register yet)
		existingPath, duplicate := GetDedupCache().Lookup(contentInfo.Hash)
		if duplicate {
			// Verify the file still exists on disk before using it
			if _, statErr := os.Stat(existingPath); statErr == nil {
				// File with identical content already exists - reuse existing path
				target = existingPath
				length = int64(len(contentInfo.DecodedContent))
				isDuplicate = true

				// Update stats
				GetDedupCache().mu.Lock()
				GetDedupCache().stats.TotalFiles++
				GetDedupCache().stats.DuplicateFiles++
				GetDedupCache().stats.BytesSaved += length
				GetDedupCache().mu.Unlock()

				saveFileLog.Info("Skipping duplicate file (content already saved)",
					zap.String("ident", conv.Ident),
					zap.String("name", name),
					zap.String("existingPath", existingPath),
					zap.String("contentHash", contentInfo.Hash),
					zap.Int64("size", length),
				)
			}
			// If file doesn't exist anymore, fall through to save it again
		}
	}

	// If not a duplicate, save the file to disk
	if !isDuplicate {
		// Handle duplicate filenames
		target = base
		n := 0
		for {
			if _, errStat := os.Stat(target); errStat != nil {
				break
			}

			if err != nil {
				target = path.Join(root, filepath.Clean("incomplete-"+name+"-"+utils.CleanIdent(conv.Ident))+"-"+strconv.Itoa(n)+ExtensionForContentType(cTypeDetected))
			} else {
				target = path.Join(root, filepath.Clean(name+"-"+utils.CleanIdent(conv.Ident))+"-"+strconv.Itoa(n)+ExtensionForContentType(cTypeDetected))
			}
			n++
		}

		// Create file for writing
		f, err := os.Create(target)
		if err != nil {
			saveFileLog.Error("failed to create file",
				zap.String("ident", conv.Ident),
				zap.String("target", target),
				zap.Error(err),
			)
			return err
		}

		// Use streaming hash writer for efficiency
		hashWriter := NewStreamingHashWriter(f)

		// Always use the fully decoded content (gzip/deflate/base64 already decoded by ComputeContentHash)
		r := bytes.NewBuffer(contentInfo.DecodedContent)

		// Copy data while computing hashes
		w, errCopy := io.Copy(hashWriter, r)
		errClose := hashWriter.Close()
		if errCopy != nil {
			saveFileLog.Error("failed to save file",
				zap.String("ident", conv.Ident),
				zap.String("target", target),
				zap.Int64("bytesWritten", w),
				zap.Error(errCopy),
			)
			_ = os.Remove(target)
			return errCopy
		} else {
			length = w
			saveFileLog.Debug("saved file",
				zap.String("ident", conv.Ident),
				zap.String("target", target),
				zap.Int64("bytesWritten", w),
			)
		}
		if errClose != nil {
			_ = os.Remove(target)
			return errClose
		}

		// Register in dedup cache AFTER successful write with final path
		if cfg.FileExtraction.Advanced.DeduplicateFiles && contentInfo.Hash != "" {
			GetDedupCache().mu.Lock()
			GetDedupCache().hashToPath[contentInfo.Hash] = target
			GetDedupCache().stats.TotalFiles++
			GetDedupCache().stats.UniqueFiles++
			GetDedupCache().mu.Unlock()
		}

		// Get computed hashes (selective based on config)
		allHashes := hashWriter.GetHashes()
		hashes = FileHashes{}

		if ShouldComputeHash("MD5") {
			hashes.MD5 = allHashes.MD5
		}
		if ShouldComputeHash("SHA1") {
			hashes.SHA1 = allHashes.SHA1
		}
		if ShouldComputeHash("SHA256") {
			hashes.SHA256 = allHashes.SHA256
		}
	} else {
		// For duplicates, compute hashes from the decoded content
		allHashes := ComputeHashes(contentInfo.DecodedContent)
		hashes = FileHashes{}

		if ShouldComputeHash("MD5") {
			hashes.MD5 = allHashes.MD5
		}
		if ShouldComputeHash("SHA1") {
			hashes.SHA1 = allHashes.SHA1
		}
		if ShouldComputeHash("SHA256") {
			hashes.SHA256 = allHashes.SHA256
		}
	}

	// Set the value for the provided content type if none was provided
	if contentType == "" {
		contentType = cTypeDetected
	}

	// Determine flow direction if not provided
	if flowDirection == "" {
		flowDirection = "unknown"
	}

	// Perform security analysis on the decompressed file content
	analysis := AnalyzeFile(contentInfo.DecodedContent, fileName)

	// AI-based file type classification (if enabled)
	var magikaResult *magikapkg.Result
	if cfg.FileExtraction.Advanced.EnableMagika && magikapkg.IsEnabled() {
		magikaResult, err = magikapkg.ClassifyBytes(contentInfo.DecodedContent)
		if err != nil {
			saveFileLog.Warn("magika classification failed",
				zap.String("name", name),
				zap.Error(err),
			)
			err = nil // don't propagate magika errors
		}
	}

	// Sanitize string fields to ensure valid UTF-8 for protobuf encoding
	sanitizedSource, sanitizedHost, sanitizedContentType, sanitizedCTypeDetected, sanitizedFlowDirection :=
		sanitizeStringFields(source, host, contentType, cTypeDetected, flowDirection)

	// Write file record with security analysis fields and compression info
	WriteFileEnhanced(&types.File{
		Timestamp:           conv.FirstClientPacket.UnixNano(),
		Name:                utils.SanitizeUTF8(fileName),
		Length:              length,
		Hash:                hashes.MD5, // Keep for backward compatibility
		Location:            target,
		Ident:               conv.Ident,
		Source:              sanitizedSource,
		ContentType:         sanitizedContentType,
		ContentTypeDetected: sanitizedCTypeDetected,
		SrcIP:               conv.ClientIP,
		DstIP:               conv.ServerIP,
		SrcPort:             conv.ServerPort,
		DstPort:             conv.ClientPort,
		Host:                sanitizedHost,
		Hashes: &types.FileHashes{
			MD5:    hashes.MD5,
			SHA1:   hashes.SHA1,
			SHA256: hashes.SHA256,
		},
		Depth:         int32(depth),
		MissingBytes:  0, // TODO: Track from reassembly
		IsComplete:    err == nil,
		ParentFileID:  utils.SanitizeUTF8(parentFileID),
		FlowDirection: sanitizedFlowDirection,
		ConnectionUID: conv.Ident,
		Protocol:      utils.SanitizeUTF8(protocol),
		// Security analysis fields
		Entropy:             analysis.Entropy,
		MagicBytes:          analysis.MagicBytes,
		TrueFileType:        utils.SanitizeUTF8(analysis.TrueFileType),
		TypeMismatch:        analysis.TypeMismatch,
		IsPEExecutable:      analysis.IsPEExecutable,
		IsELFExecutable:     analysis.IsELFExecutable,
		IsMachO:             analysis.IsMachO,
		HasEmbeddedScript:   analysis.HasEmbeddedScript,
		IsPasswordProtected: analysis.IsPasswordProtected,
		YaraMatches:         analysis.YaraMatches,
		IsKnownMalware:      analysis.IsKnownMalware,
		ThreatName:          utils.SanitizeUTF8(analysis.ThreatName),
		CommunityID:         conv.CommunityID,
		// Compression tracking fields
		WasCompressed:   contentInfo.WasCompressed,
		CompressionType: contentInfo.CompressionType,
		CompressedSize:  contentInfo.CompressedSize,
		// AI-based file type classification (Magika)
		MagikaLabel:       magikaLabel(magikaResult),
		MagikaMimeType:    magikaMimeType(magikaResult),
		MagikaGroup:       magikaGroup(magikaResult),
		MagikaDescription: magikaDescription(magikaResult),
		MagikaIsText:      magikaIsText(magikaResult),
	})

	return nil
}

// trimEncoding removes encoding information from content type
func trimEncoding(contentType string) string {
	if idx := strings.Index(contentType, ";"); idx > 0 {
		return strings.TrimSpace(contentType[:idx])
	}
	return contentType
}

// magikaLabel safely extracts the label from a possibly-nil Magika result.
func magikaLabel(r *magikapkg.Result) string {
	if r == nil {
		return ""
	}
	return r.Label
}

// magikaMimeType safely extracts the MIME type from a possibly-nil Magika result.
func magikaMimeType(r *magikapkg.Result) string {
	if r == nil {
		return ""
	}
	return r.MimeType
}

// magikaGroup safely extracts the group from a possibly-nil Magika result.
func magikaGroup(r *magikapkg.Result) string {
	if r == nil {
		return ""
	}
	return r.Group
}

// magikaDescription safely extracts the description from a possibly-nil Magika result.
func magikaDescription(r *magikapkg.Result) string {
	if r == nil {
		return ""
	}
	return r.Description
}

// magikaIsText safely extracts the IsText flag from a possibly-nil Magika result.
func magikaIsText(r *magikapkg.Result) bool {
	if r == nil {
		return false
	}
	return r.IsText
}

// createContentTypePathIfRequired creates a directory for a content type if it doesn't exist
func createContentTypePathIfRequired(path string) {
	if err := os.MkdirAll(path, defaults.DirectoryPermission); err != nil {
		saveFileLog.Error("failed to create content type directory",
			zap.String("path", path),
			zap.Error(err),
		)
	}
}
