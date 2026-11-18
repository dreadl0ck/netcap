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

package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/expr-lang/expr/vm"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	netfilter "github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// HandleAuditFiles returns list of audit record files for a given output directory
func HandleAuditFiles(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			RespondJSON(w, http.StatusOK, []AuditFileInfo{})
			return
		}

		files, err := listAuditFiles(r.Context(), outputDir)
		if err != nil {
			if errors.Is(err, errAuditInventoryLimit) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			log.Printf("[WebUI] Error listing audit files: %v", err)
			RespondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to list audit files: %v", err),
			})
			return
		}

		RespondJSON(w, http.StatusOK, files)
	}
}

// FilteredAuditFileInfo extends AuditFileInfo with filtered count
type FilteredAuditFileInfo struct {
	AuditFileInfo
	FilteredCount int64 `json:"filteredCount"`
}

// HandleAuditFilesFiltered returns list of audit record files with counts filtered by community IDs
func HandleAuditFilesFiltered(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			RespondJSON(w, http.StatusOK, []FilteredAuditFileInfo{})
			return
		}

		// Get community IDs from query parameter (comma-separated)
		communityIDsParam := r.URL.Query().Get("communityIds")
		if communityIDsParam == "" {
			// If no filter, return regular files
			files, err := listAuditFiles(r.Context(), outputDir)
			if err != nil {
				log.Printf("[WebUI] Error listing audit files: %v", err)
				RespondJSON(w, http.StatusInternalServerError, map[string]string{
					"error": fmt.Sprintf("Failed to list audit files: %v", err),
				})
				return
			}
			// Convert to FilteredAuditFileInfo with same counts
			result := make([]FilteredAuditFileInfo, len(files))
			for i, f := range files {
				result[i] = FilteredAuditFileInfo{
					AuditFileInfo: f,
					FilteredCount: f.RecordCount,
				}
			}
			RespondJSON(w, http.StatusOK, result)
			return
		}

		// Parse community IDs into a set
		communityIDs := make(map[string]bool)
		for id := range strings.SplitSeq(communityIDsParam, ",") {
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				communityIDs[trimmed] = true
			}
		}

		if len(communityIDs) == 0 {
			// Empty filter, return regular files
			files, err := listAuditFiles(r.Context(), outputDir)
			if err != nil {
				log.Printf("[WebUI] Error listing audit files: %v", err)
				RespondJSON(w, http.StatusInternalServerError, map[string]string{
					"error": fmt.Sprintf("Failed to list audit files: %v", err),
				})
				return
			}
			// Convert to FilteredAuditFileInfo with same counts
			result := make([]FilteredAuditFileInfo, len(files))
			for i, f := range files {
				result[i] = FilteredAuditFileInfo{
					AuditFileInfo: f,
					FilteredCount: f.RecordCount,
				}
			}
			RespondJSON(w, http.StatusOK, result)
			return
		}

		// List all audit files and count filtered records
		files, err := listAuditFilesWithCommunityIDFilter(r.Context(), outputDir, communityIDs)
		if err != nil {
			if errors.Is(err, errAuditInventoryLimit) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			log.Printf("[WebUI] Error listing filtered audit files: %v", err)
			RespondJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to list audit files: %v", err),
			})
			return
		}

		RespondJSON(w, http.StatusOK, files)
	}
}

// ListAuditFilesWithCommunityIDFilter returns audit files with filtered counts by community IDs
func ListAuditFilesWithCommunityIDFilter(outputDir string, communityIDs map[string]bool) ([]FilteredAuditFileInfo, error) {
	return listAuditFilesWithCommunityIDFilter(context.Background(), outputDir, communityIDs)
}

func listAuditFilesWithCommunityIDFilter(ctx context.Context, outputDir string, communityIDs map[string]bool) ([]FilteredAuditFileInfo, error) {
	var files []FilteredAuditFileInfo
	entries, err := auditInventoryEntries(ctx, outputDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !preferredAuditFile(outputDir, name) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Extract audit type
		auditType := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), defaults.FileExtension)
		filePath := filepath.Join(outputDir, name)

		totalCount, filteredCount, err := communityCountsContext(ctx, filePath, communityIDs)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", name, err)
		}

		files = append(files, FilteredAuditFileInfo{
			AuditFileInfo: AuditFileInfo{
				FileInfo: FileInfo{
					Name:         name,
					Path:         filePath,
					Size:         info.Size(),
					ModifiedTime: info.ModTime().Unix(),
					IsCompleted:  true,
				},
				Type:        auditType,
				RecordCount: totalCount,
				Layer:       GetLayerName(GetLayerType(auditType)),
			},
			FilteredCount: filteredCount,
		})
	}

	// Sort files by layer hierarchy
	sort.Slice(files, func(i, j int) bool {
		layerI := GetLayerType(files[i].Type)
		layerJ := GetLayerType(files[j].Type)
		if layerI != layerJ {
			return layerI < layerJ
		}
		return files[i].Type < files[j].Type
	})

	return files, nil
}

// CountRecordsWithCommunityIDFilter counts records that match any of the given community IDs
func CountRecordsWithCommunityIDFilter(filePath string, communityIDs map[string]bool) int64 {
	_, count, err := communityCounts(filePath, communityIDs)
	if err != nil {
		return 0
	}
	return count
}

// HandleAuditRecords streams audit records from a file
func HandleAuditRecords(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract audit type from URL path
		encodedPath := strings.TrimPrefix(r.URL.Path, "/api/audit/")
		parts := strings.Split(encodedPath, "/")
		if len(parts) < 1 {
			http.Error(w, "Invalid audit type", http.StatusBadRequest)
			return
		}

		// URL-decode the audit type
		auditType, err := url.PathUnescape(parts[0])
		if err != nil || auditType == "" || filepath.Base(auditType) != auditType || strings.ContainsAny(auditType, `/\\`) {
			http.Error(w, "Invalid audit type encoding", http.StatusBadRequest)
			return
		}

		action := "stream"
		if len(parts) > 1 {
			action = parts[1]
		}
		if sealed := partialAuditContext(r); sealed != nil && action == "stream" {
			HandleAuditStream(w, r, "", sealed.Stage.Type)
			return
		}

		// For fields action, we don't need the file to exist
		if action == "fields" {
			HandleAuditFields(w, r, auditType)
			return
		}

		filePath := filepath.Join(outputDir, auditType+defaults.FileExtension+".gz")
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			filePath = strings.TrimSuffix(filePath, ".gz")
		}
		if action == "values" {
			HandleAuditFieldValues(w, r, filePath, auditType)
			return
		}

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			RespondJSON(w, http.StatusNotFound, map[string]string{
				"error": fmt.Sprintf("Audit file not found: %s", auditType),
			})
			return
		}

		if action == "meta" {
			HandleAuditMeta(w, r, filePath, auditType)
		} else {
			HandleAuditStream(w, r, filePath, auditType)
		}
	}
}

// HandleLogFiles returns list of log files for a given output directory
func HandleLogFiles(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outputDir == "" {
			RespondJSON(w, http.StatusOK, []FileInfo{})
			return
		}

		// Look for all .log files in output directory
		var logs []FileInfo

		entries, err := os.ReadDir(outputDir)
		if err != nil {
			RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cannot read analysis log directory"})
			return
		}

		for _, entry := range entries {
			// Skip directories
			if entry.IsDir() {
				continue
			}

			name := entry.Name()

			// Only include .log files
			if !strings.HasSuffix(name, ".log") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Skip empty log files (size 0)
			if info.Size() == 0 {
				continue
			}

			logs = append(logs, FileInfo{
				Name:         name,
				Path:         filepath.Join(outputDir, name),
				Size:         info.Size(),
				ModifiedTime: info.ModTime().Unix(),
				IsCompleted:  true,
			})
		}

		// Sort logs by name for consistent ordering
		sort.Slice(logs, func(i, j int) bool {
			return logs[i].Name < logs[j].Name
		})

		RespondJSON(w, http.StatusOK, logs)
	}
}

// HandleLogContent returns the content of a log file
func HandleLogContent(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract log name from URL
		encodedLogName := strings.TrimPrefix(r.URL.Path, "/api/logs/")
		if encodedLogName == "" {
			http.Error(w, "Log name required", http.StatusBadRequest)
			return
		}

		// URL-decode the log name
		logName, err := url.PathUnescape(encodedLogName)
		if err != nil {
			http.Error(w, "Invalid log name encoding", http.StatusBadRequest)
			return
		}

		// Sanitize filename
		logName = filepath.Base(logName)
		logPath := filepath.Join(outputDir, logName)

		// Read log file
		content, err := os.ReadFile(logPath)
		if err != nil {
			http.Error(w, "Log file not found", http.StatusNotFound)
			return
		}

		// Return raw log content as plain text
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}
}

// HandleAuditStats returns statistics for specific audit record types
func HandleAuditStats(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		stats := getAuditStatsForDirectory(r.Context(), outputDir)
		if r.Context().Err() == nil {
			RespondJSON(w, http.StatusOK, stats)
		}
	}
}

func preferredAuditFile(dir, name string) bool {
	if strings.HasSuffix(name, defaults.FileExtension+".gz") {
		return true
	}
	if !strings.HasSuffix(name, defaults.FileExtension) {
		return false
	}
	_, err := os.Lstat(filepath.Join(dir, name+".gz"))
	return os.IsNotExist(err)
}

// ListAuditFiles returns a list of audit files in the given directory
func ListAuditFiles(outputDir string) ([]AuditFileInfo, error) {
	return listAuditFiles(context.Background(), outputDir)
}

const maxAuditInventoryEntries = 4096

var errAuditInventoryLimit = errors.New("audit inventory exceeds 4096 directory entries")

func auditInventoryEntries(ctx context.Context, outputDir string) ([]os.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.Open(outputDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxAuditInventoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxAuditInventoryEntries {
		return nil, errAuditInventoryLimit
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, ctx.Err()
}

func listAuditFiles(ctx context.Context, outputDir string) ([]AuditFileInfo, error) {
	entries, err := auditInventoryEntries(ctx, outputDir)
	if err != nil {
		return nil, err
	}
	var files []AuditFileInfo
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !preferredAuditFile(outputDir, name) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Extract audit type
		auditType := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), defaults.FileExtension)

		path := filepath.Join(outputDir, name)
		recordCount, countErr := countAuditFrames(ctx, path, auditType)
		complete := countErr == nil
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		files = append(files, AuditFileInfo{
			FileInfo: FileInfo{
				Name:         name,
				Path:         filepath.Join(outputDir, name),
				Size:         info.Size(),
				ModifiedTime: info.ModTime().Unix(),
				IsCompleted:  true,
			},
			Type:                auditType,
			RecordCount:         recordCount,
			RecordCountComplete: &complete,
			Layer:               GetLayerName(GetLayerType(auditType)),
		})
	}

	// Sort files by layer hierarchy
	SortAuditFiles(files)

	return files, nil
}

// CountRecords counts complete frames in an audit file.
func CountRecords(filePath string) int64 {
	if total, ok := communityCachedTotal(filePath); ok {
		return total
	}
	count, _ := countAuditFrames(context.Background(), filePath, "")
	return count
}

func countAuditFrames(ctx context.Context, filePath, auditType string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f, _, err := artifactio.Open(filepath.Dir(filePath), filepath.Base(filePath))
	if err != nil {
		return 0, err
	}
	reader, err := auditRecordReaderFromInput(f, f, strings.HasSuffix(filePath, ".gz"), func(input io.Reader) io.Reader {
		return auditContextReader{ctx: ctx, input: input}
	})
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	count := int64(0)
	header, err := reader.ReadHeader()
	if err != nil {
		return 0, err
	}
	if netio.InitRecord(header.Type) == nil {
		return 0, fmt.Errorf("unsupported audit type %v", header.Type)
	}
	if auditType != "" && header.Type.String() != "NC_"+strings.TrimPrefix(auditType, "NC_") {
		return 0, fmt.Errorf("unexpected audit header type %s for %s", header.Type, auditType)
	}

	for {
		err := reader.delimitedReader.Skip(ctx)
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		count++
	}

}

// HandleAuditMeta returns metadata for an audit file
func HandleAuditMeta(w http.ResponseWriter, r *http.Request, filePath, auditType string) {
	recordCount, err := countAuditFrames(r.Context(), filePath, auditType)

	RespondJSON(w, http.StatusOK, map[string]any{
		"type":                auditType,
		"recordCount":         recordCount,
		"recordCountComplete": err == nil,
		"recordCountBasis":    "framing",
		"filePath":            filePath,
	})
}

// HandleAuditStream streams audit records via Server-Sent Events
func HandleAuditStream(w http.ResponseWriter, r *http.Request, filePath, auditType string) {
	startTime := time.Now()
	if sealed := partialAuditContext(r); sealed != nil && sealed.File != "" {
		filePath = filepath.Join(sealed.Directory, sealed.File)
	}
	if r.URL.Query().Has("evidence") {
		handleBoundAuditStream(w, r, filePath, auditType)
		return
	}

	// Parse query parameters
	offset := 0
	limit := 500 // Default limit (max 500)
	countOnly := r.URL.Query().Get("countOnly") == "true"
	fullRecords := r.URL.Query().Get("full") == "true"
	fields := r.URL.Query().Get("fields")

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil && val >= 0 {
			offset = val
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 500 {
			limit = val
		}
	}

	// Get filter expression
	filterExpr := r.URL.Query().Get("filter")
	var communityIDs map[string]bool
	for _, id := range r.URL.Query()["communityId"] {
		if id = strings.TrimSpace(id); id != "" {
			if communityIDs == nil {
				communityIDs = make(map[string]bool)
			}
			communityIDs[id] = true
		}
	}

	// Check if streaming is supported BEFORE setting headers
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Setup SSE headers - must be done before any writes
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Helper function to send SSE error event
	sendError := func(errorMsg string) {
		errorJSON, _ := json.Marshal(map[string]string{"error": errorMsg})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(errorJSON))
		flusher.Flush()
	}

	// Create audit record reader
	if sealed := partialAuditContext(r); sealed != nil && sealed.Stage.Records == 0 {
		if filterExpr != "" {
			typ, ok := types.Type_value["NC_"+auditType]
			if !ok {
				sendError("Unknown sealed audit type")
				return
			}
			if _, err := netfilter.CompileExpression(filterExpr, types.Type(typ)); err != nil {
				sendError("Invalid filter expression: " + err.Error())
				return
			}
		}
		auditCompletion(w, r, 0, 0, 0, offset, time.Since(startTime).Milliseconds(), countOnly)
		flusher.Flush()
		return
	}
	var auditReader *AuditRecordReader
	var err error
	if sealed := partialAuditContext(r); sealed != nil {
		auditReader, err = sealed.openReader()
	} else {
		auditReader, err = NewAuditRecordReader(filePath)
	}
	if err != nil {
		log.Printf("[WebUI] Failed to open audit record file %s: %v", filePath, err)
		if err == io.EOF {
			sendError("Audit record file is incomplete or being written")
		} else {
			sendError(fmt.Sprintf("Failed to open audit record file: %v", err))
		}
		return
	}
	defer auditReader.Close()

	// Read the header first (required before reading records)
	header, err := auditReader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read header from %s: %v", filePath, err)
		if err == io.EOF {
			sendError("Audit record file is incomplete or being written")
		} else {
			sendError(fmt.Sprintf("Failed to read header: %v", err))
		}
		return
	}

	if sealed := partialAuditContext(r); sealed != nil {
		want, ok := types.Type_value["NC_"+sealed.Stage.Type]
		if !ok || header.Type != types.Type(want) {
			sendError("Audit header type does not match the sealed stage")
			return
		}
	}

	// Compile filter expression if provided
	var filterProgram *vm.Program
	if filterExpr != "" {
		filterProgram, err = netfilter.CompileExpression(filterExpr, header.Type)
		if err != nil {
			log.Printf("[WebUI] Failed to compile filter expression: %v", err)
			sendError(fmt.Sprintf("Invalid filter expression: %v", err))
			return
		}
	}
	var candidates *roaring.Bitmap
	var indexedTotal int64
	// The path-based index is not bound to the verified descriptor.
	if len(communityIDs) > 0 && partialAuditContext(r) == nil {
		candidates, indexedTotal, err = communitySelectedBitmap(r.Context(), filePath, communityIDs)
		if err != nil {
			sendError(fmt.Sprintf("Failed to index Community IDs: %v", err))
			return
		}
		if candidates != nil {
			opened, openedErr := auditReader.file.Stat()
			current, currentErr := os.Stat(filePath)
			if openedErr != nil || currentErr != nil || !os.SameFile(opened, current) ||
				opened.Size() != current.Size() || !opened.ModTime().Equal(current.ModTime()) {
				candidates = nil
			}
		}
	}

	// Stream records
	count := 0
	totalScanned := 0
	matchedCount := 0
	pageBytes := 0
	pageFull := false
	response := http.NewResponseController(w)

	for {
		if r.Context().Err() != nil {
			return
		}
		var record proto.Message
		var raw []byte
		if candidates != nil {
			raw, err = auditReader.NextRaw()
		} else {
			record, err = auditReader.NextRecord()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			sendError(err.Error())
			return
		}

		totalScanned++
		if candidates != nil && int64(totalScanned) <= indexedTotal && !candidates.Contains(uint32(totalScanned-1)) {
			continue
		}
		if candidates != nil {
			record, err = auditReader.DecodeRecord(raw)
			if err != nil {
				sendError(fmt.Sprintf("Failed to decode audit record: %v", err))
				return
			}
		}
		if len(communityIDs) > 0 && (candidates == nil || int64(totalScanned) > indexedTotal) && !auditRecordMatchesCommunityID(record, communityIDs) {
			continue
		}

		// Apply filter if provided
		if filterProgram != nil {
			auditRecord, ok := record.(types.AuditRecord)
			if !ok {
				continue
			}

			match, err := netfilter.EvaluateExpression(filterProgram, auditRecord)
			if err != nil {
				log.Printf("[WebUI] Filter evaluation error: %v", err)
				continue
			}

			if !match {
				continue
			}
			matchedCount++
		} else {
			matchedCount++
		}

		if countOnly || matchedCount <= offset {
			continue
		}

		// Only send records if we haven't reached the limit yet
		// But continue scanning to get accurate totalScanned count
		if count < limit && !pageFull {
			// Convert record to JSON
			jsonData, err := json.Marshal(record)
			if err != nil {
				log.Printf("[WebUI] JSON marshal error: %v", err)
				continue
			}

			// Truncate large records to prevent UI issues with very large record types (e.g., DeviceProfile)
			const maxRecordSize = 2000
			if fullRecords {
				jsonData, err = projectRecordJSON(jsonData, fields)
				if err != nil {
					sendError(err.Error())
					return
				}
				if len(jsonData) > 16<<20 {
					sendError("record exceeds 16 MiB; select smaller fields with fields")
					return
				}
				if count > 0 && pageBytes+len(jsonData) > 80<<10 {
					pageFull = true
					continue
				}
				pageBytes += len(jsonData)
			} else if len(jsonData) > maxRecordSize {
				// Create a truncated response with valid JSON structure
				truncatedData := map[string]any{
					"_truncated":     true,
					"_originalSize":  len(jsonData),
					"_truncatedData": string(jsonData[:maxRecordSize]) + "...",
				}
				jsonData, _ = json.Marshal(truncatedData)
			}

			if _, err := fmt.Fprintf(w, "event: record\ndata: %s\n\n", jsonData); err != nil {
				return
			}
			if err := response.Flush(); err != nil {
				return
			}

			count++

			// Send progress update every 100 records returned
			if count%100 == 0 {
				if _, err := fmt.Fprintf(w, "event: progress\ndata: {\"count\": %d, \"scanned\": %d}\n\n", count, totalScanned); err != nil {
					return
				}
				if err := response.Flush(); err != nil {
					return
				}
			}
		}

		// Continue scanning all records even after reaching limit
		// to get accurate totalScanned count
	}

	executionTime := time.Since(startTime)

	// Send completion event with execution time
	if sealed := partialAuditContext(r); sealed != nil {
		if int64(totalScanned) != sealed.Stage.Records {
			sendError("Sealed audit record count changed")
			return
		}
		if err := sealed.verifyCompletion(r.Context()); err != nil {
			if r.Context().Err() != nil {
				return
			}
			sendError("Sealed audit output changed during query")
			return
		}
	}
	auditCompletion(w, r, matchedCount, totalScanned, count, offset, executionTime.Milliseconds(), countOnly)
	flusher.Flush()
}

// FieldsResponse is the API response for field information
type FieldsResponse struct {
	RecordType string      `json:"recordType"`
	Fields     []FieldInfo `json:"fields"`
	Helpers    []string    `json:"helpers"`
}

// HandleAuditFields returns field information for a specific audit record type
func HandleAuditFields(w http.ResponseWriter, r *http.Request, recordTypeName string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Convert type name to Type enum
	recordType := types.Type(types.Type_value["NC_"+recordTypeName])
	if recordType == 0 { // 0 is the default/unknown type
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("Unknown record type: %s", recordTypeName),
		})
		return
	}

	// Create a sample record to extract field information
	record := netio.InitRecord(recordType)
	if record == nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("Failed to initialize record type: %s", recordTypeName),
		})
		return
	}

	// Extract fields using reflection
	fields := extractFields(record, "", 0)

	// Add helper functions
	helpers := []string{
		"InSubnet",
		"IsPrivateIP",
		"IsPublicIP",
		"ParsePort",
		"PortInRange",
		"TimeInRange",
		"DurationSince",
		"FormatTime",
		"ContainsAny",
		"MatchesPattern",
	}

	RespondJSON(w, http.StatusOK, FieldsResponse{
		RecordType: recordTypeName,
		Fields:     fields,
		Helpers:    helpers,
	})
}

// extractFields recursively extracts field information from a struct
func extractFields(v any, prefix string, depth int) []FieldInfo {
	fields := make([]FieldInfo, 0)

	// Limit recursion depth to avoid explosion
	if depth > 2 {
		return fields
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return fields
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fields
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Skip XXX_ fields (protobuf internal)
		if strings.HasPrefix(field.Name, "XXX_") {
			continue
		}

		fieldName := field.Name
		if prefix != "" {
			fieldName = prefix + "." + field.Name
		}

		fieldType := field.Type.String()

		// Add the field
		fields = append(fields, FieldInfo{
			Name: fieldName,
			Type: fieldType,
		})

		// For nested structs, recursively extract fields
		if field.Type.Kind() == reflect.Struct && depth < 2 {
			nestedFields := extractFields(fieldValue.Interface(), fieldName, depth+1)
			fields = append(fields, nestedFields...)
		}

		// For pointer to struct
		if field.Type.Kind() == reflect.Pointer && field.Type.Elem().Kind() == reflect.Struct && depth < 2 {
			// Create a new instance for reflection
			if !fieldValue.IsNil() {
				nestedFields := extractFields(fieldValue.Interface(), fieldName, depth+1)
				fields = append(fields, nestedFields...)
			} else {
				// Try to create a new instance to get field names
				newInstance := reflect.New(field.Type.Elem())
				nestedFields := extractFields(newInstance.Interface(), fieldName, depth+1)
				fields = append(fields, nestedFields...)
			}
		}

		// For slices of structs, show array notation
		if field.Type.Kind() == reflect.Slice && depth < 2 {
			elemType := field.Type.Elem()
			if elemType.Kind() == reflect.Pointer {
				elemType = elemType.Elem()
			}
			if elemType.Kind() == reflect.Struct {
				// Create sample element for reflection
				sampleElem := reflect.New(elemType).Interface()
				nestedFields := extractFields(sampleElem, fieldName+"[0]", depth+1)
				fields = append(fields, nestedFields...)
			}
		}
	}

	return fields
}

// FieldValuesResponse is the API response for field values
type FieldValuesResponse struct {
	RecordType    string              `json:"recordType"`
	FieldValues   map[string][]string `json:"fieldValues"`
	SampleSize    int                 `json:"sampleSize"`
	MaxPerField   int                 `json:"maxPerField"`
	RecordScanned int                 `json:"recordsScanned"`
}

var auditFieldSampleSlots = make(chan struct{}, 2)

// HandleAuditFieldValues returns sample values for fields in a specific audit record type.
func HandleAuditFieldValues(w http.ResponseWriter, r *http.Request, filePath, recordTypeName string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Context().Err() != nil {
		http.Error(w, "Audit field lookup canceled", http.StatusRequestTimeout)
		return
	}

	select {
	case auditFieldSampleSlots <- struct{}{}:
		defer func() { <-auditFieldSampleSlots }()
	default:
		http.Error(w, "Audit field lookups are busy", http.StatusTooManyRequests)
		return
	}
	f, _, err := artifactio.Open(filepath.Dir(filePath), filepath.Base(filePath))
	if errors.Is(err, os.ErrNotExist) {
		RespondJSON(w, http.StatusNotFound, map[string]any{
			"error": fmt.Sprintf("Audit file not found: %s", recordTypeName),
		})
		return
	}
	if err != nil {
		artifactAccessError(w, err)
		return
	}

	ctx := r.Context()
	reader, err := auditRecordReaderFromInput(f, f, strings.HasSuffix(filePath, ".gz"), func(input io.Reader) io.Reader {
		return auditContextReader{ctx: ctx, input: input}
	})
	if err != nil {
		if ctx.Err() != nil {
			http.Error(w, "Audit field lookup canceled", http.StatusRequestTimeout)
			return
		}
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to open audit record file: %v", err),
		})
		return
	}
	defer reader.Close()

	// Read header
	header, err := reader.ReadHeader()
	if err != nil {
		if ctx.Err() != nil {
			http.Error(w, "Audit field lookup canceled", http.StatusRequestTimeout)
			return
		}
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to read header: %v", err),
		})
		return
	}
	if header.Type.String() != "NC_"+strings.TrimPrefix(recordTypeName, "NC_") {
		http.Error(w, "Unexpected audit header type", http.StatusInternalServerError)
		return
	}

	const maxValuesPerField = 20
	const maxRecordsToScan = 200
	const maxSampleBytes = 16 << 20
	const maxSampleValueBytes = 128 << 10

	// Map to collect unique values per field
	fieldValues := make(map[string]map[string]bool)
	recordsScanned := 0
	remaining := maxSampleBytes
	valueBytes := maxSampleValueBytes

	// Read records and collect values
	for recordsScanned < maxRecordsToScan {
		if r.Context().Err() != nil {
			http.Error(w, "Audit field lookup canceled", http.StatusRequestTimeout)
			return
		}
		raw, err := reader.delimitedReader.NextWithLimit(uint64(max(1, remaining)))
		if ctx.Err() != nil {
			http.Error(w, "Audit field lookup canceled", http.StatusRequestTimeout)
			return
		}
		if err == io.EOF {
			break
		}
		if errors.Is(err, delimited.ErrRecordLimit) || len(raw) > remaining {
			http.Error(w, "Audit field sample exceeds 16 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		var record proto.Message
		if err == nil {
			record, err = reader.DecodeRecord(raw)
		}
		if err != nil {
			log.Printf("[WebUI] Error reading record: %v", err)
			http.Error(w, "Cannot read audit field values", http.StatusInternalServerError)
			return
		}

		recordsScanned++
		remaining -= len(raw)

		// Extract field values using reflection
		extractFieldValues(record, "", fieldValues, maxValuesPerField, 0, &valueBytes)
		if valueBytes < 0 {
			http.Error(w, "Audit field sample values exceed 128 KiB", http.StatusRequestEntityTooLarge)
			return
		}
	}

	// Convert to response format
	result := make(map[string][]string)
	for fieldName, valuesMap := range fieldValues {
		values := make([]string, 0, len(valuesMap))
		for value := range valuesMap {
			values = append(values, value)
		}
		sort.Strings(values)
		result[fieldName] = values
	}

	RespondJSON(w, http.StatusOK, FieldValuesResponse{
		RecordType:    recordTypeName,
		FieldValues:   result,
		SampleSize:    maxRecordsToScan,
		MaxPerField:   maxValuesPerField,
		RecordScanned: recordsScanned,
	})
}

// extractFieldValues recursively extracts unique field values from a struct
func extractFieldValues(v any, prefix string, fieldValues map[string]map[string]bool, maxPerField int, depth int, remaining *int) {
	// Limit recursion depth
	if depth > 2 {
		return
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Skip XXX_ fields (protobuf internal)
		if strings.HasPrefix(field.Name, "XXX_") {
			continue
		}

		fieldName := field.Name
		if prefix != "" {
			fieldName = prefix + "." + field.Name
		}

		// Initialize map for this field if needed
		if _, exists := fieldValues[fieldName]; !exists {
			fieldValues[fieldName] = make(map[string]bool)
		}

		// Skip if we already have max values for this field
		if len(fieldValues[fieldName]) >= maxPerField {
			continue
		}

		// Extract value based on type
		if *remaining < 0 {
			return
		}
		if !fieldValue.CanInterface() {
			continue
		}

		var sample string
		switch field.Type.Kind() {
		case reflect.String:
			sample = fieldValue.String()

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			sample = strconv.FormatInt(fieldValue.Int(), 10)

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			sample = strconv.FormatUint(fieldValue.Uint(), 10)

		case reflect.Float32, reflect.Float64:
			sample = strconv.FormatFloat(fieldValue.Float(), 'g', -1, 64)

		case reflect.Bool:
			sample = strconv.FormatBool(fieldValue.Bool())

		case reflect.Struct:
			// Recurse into nested struct
			if depth < 2 {
				extractFieldValues(fieldValue.Interface(), fieldName, fieldValues, maxPerField, depth+1, remaining)
			}

		case reflect.Pointer:
			if !fieldValue.IsNil() && field.Type.Elem().Kind() == reflect.Struct && depth < 2 {
				extractFieldValues(fieldValue.Interface(), fieldName, fieldValues, maxPerField, depth+1, remaining)
			}

		case reflect.Slice:
			// For slices, sample first few elements
			if fieldValue.Len() > 0 {
				elemType := field.Type.Elem()
				if elemType.Kind() == reflect.Pointer {
					elemType = elemType.Elem()
				}

				if elemType.Kind() == reflect.Struct && depth < 2 {
					// Sample first element with array notation
					firstElem := fieldValue.Index(0)
					extractFieldValues(firstElem.Interface(), fieldName+"[0]", fieldValues, maxPerField, depth+1, remaining)
				}
			}
		}
		if sample != "" && !fieldValues[fieldName][sample] {
			*remaining -= len(sample)
			if *remaining < 0 {
				return
			}
			fieldValues[fieldName][sample] = true
		}
	}
}
