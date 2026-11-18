package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const (
	maxCollectionPageRows      = 65536
	maxCollectionPageScanBytes = 16 << 20
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
	limit, offset := 100, 0
	for name, target := range map[string]*int{"pageLimit": &limit, "pageOffset": &offset} {
		if values, ok := q[name]; ok {
			if len(values) != 1 {
				return fail(400, fmt.Errorf("duplicate %s", name))
			}
			value, err := strconv.Atoi(values[0])
			if err != nil || value < 0 || value > 1000000000 || (name == "pageLimit" && (value < 1 || value > 500)) {
				return fail(400, fmt.Errorf("invalid %s", name))
			}
			*target = value
		}
	}
	value := reflect.ValueOf(rows)
	if value.Kind() != reflect.Slice {
		return fail(500, fmt.Errorf("collection is not a slice"))
	}
	if value.Len() > maxCollectionPageRows {
		return fail(http.StatusRequestEntityTooLarge, fmt.Errorf("collection exceeds %d scan rows", maxCollectionPageRows))
	}
	items := make([]json.RawMessage, 0, min(limit, value.Len()))
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
	hash := sha256.New()
	query := r.URL.Query()
	for _, field := range []string{"pageOffset", "pageLimit", "pageGeneration"} {
		query.Del(field)
	}
	hash.Write([]byte(r.URL.Path + "\x00" + key + "\x00" + query.Encode() + "\x00"))
	for _, extra := range metadata {
		raw, err := json.Marshal(extra)
		if err != nil {
			return fail(500, err)
		}
		hash.Write(raw)
		hash.Write([]byte{0})
	}
	for _, item := range items {
		hash.Write(item)
		hash.Write([]byte{0})
	}
	generation := hex.EncodeToString(hash.Sum(nil))
	if expected := q.Get("pageGeneration"); expected != "" && expected != generation {
		return fail(409, fmt.Errorf("collection generation changed; restart pagination"))
	}
	page := make([]json.RawMessage, 0)
	used := 0
	for i := offset; i < len(items) && len(page) < limit; i++ {
		raw, err := projectRecordJSON(items[i], q.Get("pageFields"))
		if err != nil {
			return fail(400, err)
		}
		if len(raw) > 8<<20 {
			return fail(413, fmt.Errorf("row exceeds 8 MiB; select smaller fields"))
		}
		if len(page) > 0 && used+len(raw) > 80<<10 {
			break
		}
		page = append(page, raw)
		used += len(raw)
	}
	next := offset + len(page)
	response := map[string]any{key: page, "totalCount": len(items), "limit": limit, "offset": offset, "returned": len(page), "next_offset": next, "has_more": next < len(items), "generation": generation}
	for _, extra := range metadata {
		for name, value := range extra {
			response[name] = value
		}
	}
	RespondJSON(w, 200, response)
	return true
}
