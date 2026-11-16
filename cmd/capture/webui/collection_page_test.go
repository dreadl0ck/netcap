package webui

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCollectionPagesAreBoundedStableAndSearchable(t *testing.T) {
	rows := []map[string]any{}
	for i := 149; i >= 0; i-- {
		rows = append(rows, map[string]any{"name": string(rune(1000 + i)), "banner": strings.Repeat("large", 1000), "match": "needle"})
	}
	read := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		if !respondCollectionPage(w, httptest.NewRequest("GET", "/?mcpPage=true&"+query, nil), rows, "services") {
			t.Fatal("paging not enabled")
		}
		return w
	}
	type page struct {
		Rows             []json.RawMessage `json:"services"`
		Total            int               `json:"totalCount"`
		Returned, Offset int
		Next             int  `json:"next_offset"`
		More             bool `json:"has_more"`
		Generation       string
	}
	offset, total, generation := 0, 0, ""
	seen := map[string]bool{}
	for {
		w := read("pageLimit=100&pageOffset=" + fmt.Sprint(offset) + "&pageSearch=NEEDLE&pageGeneration=" + generation)
		if w.Code != 200 || w.Body.Len() > 200<<10 {
			t.Fatalf("bad page: %d %d %s", w.Code, w.Body.Len(), w.Body.String())
		}
		var got page
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Total != 150 || got.Returned != len(got.Rows) || got.Next <= offset {
			t.Fatalf("invalid continuation: %+v", got)
		}
		if generation != "" && got.Generation != generation {
			t.Fatal("unstable generation")
		}
		for _, row := range got.Rows {
			if seen[string(row)] {
				t.Fatal("repeated page row")
			}
			seen[string(row)] = true
		}
		generation, offset = got.Generation, got.Next
		total += got.Returned
		if !got.More {
			break
		}
	}
	if total != 150 {
		t.Fatal("lost rows", total)
	}
	for _, query := range []string{"pageSearch=absent", "pageOffset=9999", "pageFields=name&pageLimit=1"} {
		w := read(query)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	rows[0]["match"] = "changed"
	if w := read("pageGeneration=" + url.QueryEscape(generation)); w.Code != 409 {
		t.Fatal("stale generation accepted")
	}
	for _, query := range []string{"pageLimit=0", "pageLimit=-1", "pageLimit=501", "pageOffset=-1", "pageOffset=1.5", "pageLimit=1&pageLimit=2"} {
		if w := read(query); w.Code != 400 {
			t.Fatal("invalid paging accepted", query)
		}
	}
}
