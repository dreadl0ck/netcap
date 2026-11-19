package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const (
	maxCollectionPageRows      = 65536
	maxCollectionPageScanBytes = 16 << 20
	maxCollectionMetadataBytes = 1 << 20
)

func respondCollectionPage(w http.ResponseWriter, r *http.Request, rows any, key string, metadata ...map[string]any) bool {
	return respondCollectionPageFiltered(w, r, rows, key, false, metadata...)
}

func respondFilteredCollectionPage(w http.ResponseWriter, r *http.Request, rows any, key string, metadata ...map[string]any) bool {
	return respondCollectionPageFiltered(w, r, rows, key, true, metadata...)
}

func respondCollectionPageFiltered(w http.ResponseWriter, r *http.Request, rows any, key string, searchApplied bool, metadata ...map[string]any) bool {
	q := r.URL.Query()
	if q.Get("mcpPage") != "true" {
		return false
	}
	fail := func(status int, err error) bool {
		RespondJSON(w, status, map[string]string{"error": err.Error()})
		return true
	}
	options, err := parseCollectionPage(r)
	if err != nil {
		return fail(400, err)
	}
	value := reflect.ValueOf(rows)
	if value.Kind() != reflect.Slice {
		return fail(500, fmt.Errorf("collection is not a slice"))
	}
	if value.Len() > maxCollectionPageRows {
		return fail(http.StatusRequestEntityTooLarge, fmt.Errorf("collection exceeds %d scan rows", maxCollectionPageRows))
	}
	items := make([]json.RawMessage, 0, min(options.limit, value.Len()))
	scannedBytes := 0
	search := strings.ToLower(q.Get("pageSearch"))
	if searchApplied {
		search = ""
	}
	for i := 0; i < value.Len(); i++ {
		if err := r.Context().Err(); err != nil {
			return true
		}
		raw, err := json.Marshal(value.Index(i).Interface())
		if err != nil {
			return fail(500, err)
		}
		if len(raw) > maxCollectionPageScanBytes-scannedBytes {
			return fail(http.StatusRequestEntityTooLarge, fmt.Errorf("collection exceeds %d encoded scan bytes", maxCollectionPageScanBytes))
		}
		scannedBytes += len(raw)
		if search == "" || strings.Contains(strings.ToLower(string(raw)), search) {
			items = append(items, raw)
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return bytes.Compare(items[i], items[j]) < 0 })
	return respondSortedCollectionPage(w, r, key, options, func(yield func(json.RawMessage, error) bool) {
		for _, item := range items {
			if !yield(item, nil) {
				return
			}
		}
	}, metadata...)
}

type collectionPageOptions struct {
	limit, offset int
}

func parseCollectionPage(r *http.Request) (collectionPageOptions, error) {
	q := r.URL.Query()
	options := collectionPageOptions{limit: 100}
	for _, name := range []string{"mcpPage", "pageLimit", "pageOffset", "pageSearch", "pageFields", "pageGeneration"} {
		if len(q[name]) > 1 {
			return options, fmt.Errorf("duplicate %s", name)
		}
	}
	for _, option := range []struct {
		name   string
		target *int
	}{{"pageLimit", &options.limit}, {"pageOffset", &options.offset}} {
		name, target := option.name, option.target
		if values, ok := q[name]; ok {
			value, err := strconv.Atoi(values[0])
			if err != nil || value < 0 || value > 1000000000 || (name == "pageLimit" && (value < 1 || value > 500)) {
				return options, fmt.Errorf("invalid %s", name)
			}
			*target = value
		}
	}
	_, err := parseRecordProjection(q.Get("pageFields"))
	return options, err
}

func respondSortedCollectionPage(w http.ResponseWriter, r *http.Request, key string, options collectionPageOptions, items iter.Seq2[json.RawMessage, error], metadata ...map[string]any) bool {
	fail := func(status int, err error) bool {
		RespondJSON(w, status, map[string]string{"error": err.Error()})
		return true
	}
	q := r.URL.Query()
	limit, offset := options.limit, options.offset
	projection, err := parseRecordProjection(q.Get("pageFields"))
	if err != nil {
		return fail(400, err)
	}
	hash := sha256.New()
	query := r.URL.Query()
	for _, field := range []string{"pageOffset", "pageLimit", "pageGeneration"} {
		query.Del(field)
	}
	hash.Write([]byte(r.URL.Path + "\x00" + key + "\x00" + query.Encode() + "\x00"))
	var extraFields map[string]json.RawMessage
	remainingMetadata := maxCollectionMetadataBytes
	for _, extra := range metadata {
		raw, err := json.Marshal(extra)
		if err != nil {
			return fail(500, err)
		}
		if len(raw) > remainingMetadata {
			return fail(http.StatusRequestEntityTooLarge, fmt.Errorf("collection metadata exceeds %d encoded bytes", maxCollectionMetadataBytes))
		}
		remainingMetadata -= len(raw)
		hash.Write(raw)
		hash.Write([]byte{0})
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return fail(500, err)
		}
		if extraFields == nil {
			extraFields = fields
		} else {
			for name, field := range fields {
				extraFields[name] = field
			}
		}
	}
	page := make([]json.RawMessage, 0)
	used, total := 0, 0
	pageFull := false
	var pageErr error
	pageStatus := 400
	for item, err := range items {
		if r.Context().Err() != nil {
			return true
		}
		if err != nil {
			return fail(500, err)
		}
		hash.Write(item)
		hash.Write([]byte{0})
		total++
		if total <= offset || len(page) == limit || pageFull {
			continue
		}
		raw, err := applyRecordProjection(item, projection)
		if err != nil {
			pageErr, pageFull = err, true
			continue
		}
		if len(raw) > 8<<20 {
			pageErr, pageStatus, pageFull = fmt.Errorf("row exceeds 8 MiB; select smaller fields"), 413, true
			continue
		}
		if len(page) > 0 && used+len(raw) > 80<<10 {
			pageFull = true
			continue
		}
		page = append(page, raw)
		used += len(raw)
	}
	generation := hex.EncodeToString(hash.Sum(nil))
	if expected := q.Get("pageGeneration"); expected != "" && expected != generation {
		return fail(409, fmt.Errorf("collection generation changed; restart pagination"))
	}
	if pageErr != nil {
		return fail(pageStatus, pageErr)
	}
	next := offset + len(page)
	response := map[string]any{key: page, "totalCount": total, "limit": limit, "offset": offset, "returned": len(page), "next_offset": next, "has_more": next < total, "generation": generation}
	for name, field := range extraFields {
		response[name] = field
	}
	RespondJSON(w, 200, response)
	return true
}
