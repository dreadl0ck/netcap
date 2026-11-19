package webui

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type cancelingAuditInput struct {
	io.Reader
	read   int
	cancel func()
}

func (r *cancelingAuditInput) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += n
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	return n, err
}

func TestReproductionHashStopsOnCancellation(t *testing.T) {
	data := bytes.Repeat([]byte("capture"), 64<<10)
	for _, name := range []string{"request", "shutdown"} {
		t.Run(name, func(t *testing.T) {
			canceled := make(chan struct{})
			var stop, shutdown <-chan struct{}
			if name == "request" {
				stop = canceled
			} else {
				shutdown = canceled
			}
			input := &cancelingAuditInput{Reader: bytes.NewReader(data), cancel: func() { close(canceled) }}
			if got := hashReproductionInput(input, int64(len(data)), stop, shutdown); got != (reproductionSource{}) {
				t.Fatalf("published a partial digest: %+v", got)
			}
			if input.read == 0 || input.read > 64<<10 {
				t.Fatalf("read %d bytes before stopping", input.read)
			}
		})
	}
	if got := hashReproductionInput(bytes.NewReader(data), int64(len(data)), nil, nil); got.SHA256 != digestBytes(data) || got.Bytes != int64(len(data)) {
		t.Fatalf("uncanceled digest changed: %+v", got)
	}
}

func TestRuleAuditStopsWhileReadingLargeRecord(t *testing.T) {
	var data bytes.Buffer
	w := delimited.NewWriter(&data)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_HTTP}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutProto(&types.HTTP{RequestBody: make([]byte, 256<<10)}); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "audit")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	input := &cancelingAuditInput{Reader: bytes.NewReader(data.Bytes())}
	r, err := auditRecordReaderFromInput(f, input, false, func(input io.Reader) io.Reader {
		return analysisStopReader{input: input, stop: stop}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	input.cancel = func() { close(stop) }
	if record, err := r.NextRecord(); record != nil || !errors.Is(err, errAnalysisStopping) || input.read >= data.Len() {
		t.Fatalf("canceled record read: record=%T err=%v read=%d", record, err, input.read)
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(data.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = os.CreateTemp(t.TempDir(), "compressed-audit")
	if err != nil {
		t.Fatal(err)
	}
	stop = make(chan struct{})
	compressedInput := bytes.NewReader(compressed.Bytes())
	var decoded *cancelingAuditInput
	r, err = auditRecordReaderFromInput(f, compressedInput, true, func(input io.Reader) io.Reader {
		if input != compressedInput {
			decoded = &cancelingAuditInput{Reader: input}
			input = decoded
		}
		return analysisStopReader{input: input, stop: stop}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	if decoded == nil || compressedInput.Len() != 0 {
		t.Fatal("fixture must buffer all compressed bytes before canceling")
	}
	decoded.cancel = func() { close(stop) }
	if record, err := r.NextRecord(); record != nil || !errors.Is(err, errAnalysisStopping) || decoded.read >= data.Len() {
		t.Fatalf("canceled gzip record: record=%T err=%v decoded=%d", record, err, decoded.read)
	}
}

func TestManualRuleBatchPreservesPerRuleResults(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Method: "GET"}, &types.HTTP{Method: "POST"},
	})
	selected := []*rules.Rule{
		{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true},
		{Name: "invalid", Type: "HTTP", Expression: `Method ==`, Enabled: true},
		{Name: "post", Type: "HTTP", Expression: `Method == "POST"`, Enabled: true},
		{Name: "missing", Type: "DNS", Expression: `true`, Enabled: true},
	}
	results, err := (&Server{}).replayManualRules(dir, selected, nil)
	if err != nil || len(results) != 4 {
		t.Fatal(results, err)
	}
	for _, i := range []int{0, 2} {
		if r := results[i]; !r.Success || r.AlertsCount != 1 || r.RecordsRead != 2 {
			t.Fatalf("unexpected rule result: %+v", r)
		}
	}
	if results[1].Success || results[1].Error == "" || !results[3].Success || results[3].RecordsRead != 0 {
		t.Fatal(results)
	}
}

func TestExecuteAllRulesReportsPartialFailure(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	s := &Server{outDir: dir, rulesConfig: &rules.Config{Rules: []*rules.Rule{
		{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true},
		{Name: "invalid", Type: "HTTP", Expression: `Method ==`, Enabled: true},
	}}}
	func() {
		for range cap(manualRuleSlots) {
			manualRuleSlots <- struct{}{}
			defer func() { <-manualRuleSlots }()
		}
		w := httptest.NewRecorder()
		s.handleExecuteAllRules(w, httptest.NewRequest(http.MethodPost, "/api/rules/execute-all", nil))
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("saturated replay: %d %s", w.Code, w.Body.String())
		}
	}()
	w := httptest.NewRecorder()
	s.handleExecuteAllRules(w, httptest.NewRequest(http.MethodPost, "/api/rules/execute-all", nil))
	var result ExecuteAllRulesResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Success ||
		result.TotalAlerts != 1 || result.TotalRecords != 1 || len(result.RuleResults) != 2 ||
		!result.RuleResults[0].Success || result.RuleResults[1].Success || result.RuleResults[1].Error == "" {
		t.Fatalf("partial replay response: %d %s", w.Code, w.Body.String())
	}
}

func TestRuleAuditRejectsLinkedPreferredTrack(t *testing.T) {
	dir := t.TempDir()
	rows := []proto.Message{&types.HTTP{Method: "GET"}}
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, rows)
	linked := writeTimelineAuditFile(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, rows)
	if err := os.Symlink(linked, filepath.Join(dir, "HTTP.ncap.gz")); err != nil {
		t.Fatal(err)
	}
	count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(types.AuditRecord) error {
		t.Fatal("rule replay visited a record despite the rejected preferred input")
		return nil
	})
	if count != 0 || !errors.Is(err, artifactio.ErrPath) {
		t.Fatalf("linked preferred input: records=%d, err=%v", count, err)
	}
}

func TestOrderedRuleAuditsShareScratch(t *testing.T) {
	dir := t.TempDir()
	payload := strings.Repeat("x", 1<<20)
	rows := make([]proto.Message, 5)
	for i := range rows {
		rows[i] = &types.HTTP{Timestamp: int64(i + 1), URL: payload}
	}
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, rows)
	scratch := &ruleOrderScratch{limit: 6 << 20}
	checked := false
	visit := func(types.AuditRecord) error { t.Fatal("refused replay reached evaluation"); return nil }
	count, err := scanOrderedRuleAuditWithScratch(dir, "HTTP", nil, nil, func(types.AuditRecord) error {
		if !checked {
			checked = true
			if n, err := scanOrderedRuleAuditWithScratch(dir, "HTTP", nil, nil, visit, scratch); n != 0 || !errors.Is(err, errRuleOrderScratchFull) {
				t.Fatalf("competing replay returned %d, %v", n, err)
			}
		}
		return nil
	}, scratch)
	if err != nil || count != len(rows) || !checked || scratch.used.Load() != 0 {
		t.Fatalf("replayed %d rows, checked=%t, scratch=%d, err=%v", count, checked, scratch.used.Load(), err)
	}
	if n, err := scanOrderedRuleAuditWithScratch(dir, "HTTP", nil, nil, func(types.AuditRecord) error { return nil }, scratch); n != len(rows) || err != nil {
		t.Fatalf("replay after cleanup returned %d, %v", n, err)
	}
}

func TestOrderedRuleAuditPreservesRecordsAcrossSpill(t *testing.T) {
	dir := t.TempDir()
	payload := strings.Repeat("x", 1<<20)
	writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{
		&types.HTTP{Timestamp: 3, URL: payload},
		&types.HTTP{Timestamp: 1, URL: payload},
		&types.HTTP{Timestamp: 2, URL: payload},
		&types.HTTP{Timestamp: 1, URL: payload},
		&types.HTTP{Timestamp: -1, URL: payload},
	})
	want := []int64{-1, 1, 1, 2, 3}
	i := 0
	count, err := scanOrderedRuleAudit(dir, "HTTP", nil, nil, func(row types.AuditRecord) error {
		if i >= len(want) || row.Time() != want[i] || row.(*types.HTTP).URL != payload {
			t.Fatalf("unexpected replay record at %d: timestamp=%d", i, row.Time())
		}
		i++
		return nil
	})
	if err != nil || count != len(want) || i != count {
		t.Fatalf("replayed %d records, visited %d, error: %v", count, i, err)
	}
}

func TestRuleAuditRejectsGenerationChangesDuringReplay(t *testing.T) {
	for _, change := range []string{"append", "replace", "publish preferred gzip"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			original := &types.HTTP{Method: "GET"}
			path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{original})
			count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(record types.AuditRecord) error {
				if got := record.(*types.HTTP).Method; got != "GET" {
					t.Fatalf("replay consumed an unselected row: %q", got)
				}
				if change == "append" {
					f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					return delimited.NewWriter(f).PutProto(&types.HTTP{Method: "PUT"})
				}
				if change == "publish preferred gzip" {
					writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "PUT"}})
					return nil
				}
				opened, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				replacement := writeTimelineAuditFilePlain(t, t.TempDir(), "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "PUT"}})
				if err := os.Chtimes(replacement, opened.ModTime(), opened.ModTime()); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(replacement)
				if err != nil || info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) {
					t.Fatalf("replacement must match source metadata: %v", err)
				}
				return os.Rename(replacement, path)
			})
			if count != 1 || !errors.Is(err, errRuleAuditChanged) {
				t.Fatalf("scan: count=%d err=%v", count, err)
			}
		})
	}
}

func TestRuleAuditRejectsMissingRecordBody(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte{8})
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(types.AuditRecord) error { return nil })
	if count != 1 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(count, err)
	}
}

func TestRuleAuditFrameLimit(t *testing.T) {
	t.Run("exact_gzip", func(t *testing.T) {
		dir := t.TempDir()
		row := &types.HTTP{URL: strings.Repeat("a", maxRuleAuditFrameBytes)}
		row.URL = row.URL[:2*maxRuleAuditFrameBytes-proto.Size(row)]
		if proto.Size(row) != maxRuleAuditFrameBytes {
			t.Fatal("fixture must fill the frame budget exactly")
		}
		writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{row})
		count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(record types.AuditRecord) error {
			if record.(*types.HTTP).URL != row.URL {
				t.Fatal("replay changed the exact-limit record")
			}
			return nil
		})
		if count != 1 || err != nil {
			t.Fatalf("exact limit: count=%d err=%v", count, err)
		}
	})
	t.Run("over_plain", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, nil)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(binary.AppendUvarint(nil, maxRuleAuditFrameBytes+1))
		if err := errors.Join(err, f.Close()); err != nil {
			t.Fatal(err)
		}
		count, err := scanRuleAudit(dir, "HTTP", nil, nil, func(types.AuditRecord) error {
			t.Fatal("oversized frame reached replay")
			return nil
		})
		if count != 0 || !errors.Is(err, delimited.ErrRecordLimit) {
			t.Fatalf("over limit: count=%d err=%v", count, err)
		}
	})
}

func TestManualRuleReplayStopsOnRequestOrShutdown(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFilePlain(t, dir, "HTTP", types.Type_NC_HTTP, []proto.Message{&types.HTTP{Method: "GET"}, &types.HTTP{Method: "GET"}})
	for _, shutdown := range []bool{false, true} {
		done := make(chan struct{})
		s, request := &Server{}, done
		if shutdown {
			s.shutdownChan, request = done, nil
		}
		count, err := scanRuleAudit(dir, "HTTP", request, s.shutdownChan, func(types.AuditRecord) error {
			close(done)
			return nil
		})
		if count != 1 || !errors.Is(err, errAnalysisStopping) {
			t.Fatalf("shutdown=%t: count=%d, err=%v", shutdown, count, err)
		}
		// An absent track normally succeeds without reading any records.
		count, err = scanRuleAudit(dir, "UDP", request, s.shutdownChan, func(types.AuditRecord) error {
			t.Fatal("canceled scan visited a record")
			return nil
		})
		if count != 0 || !errors.Is(err, errAnalysisStopping) {
			t.Fatalf("shutdown=%t: canceled scan of absent track: count=%d, err=%v", shutdown, count, err)
		}
		selected := []*rules.Rule{{Name: "get", Type: "HTTP", Expression: `Method == "GET"`, Enabled: true}}
		if results, err := s.replayManualRules(dir, selected, request); len(results) != 0 || !errors.Is(err, errAnalysisStopping) {
			t.Fatalf("shutdown=%t: canceled replay admitted: %v, %v", shutdown, results, err)
		}
	}
}
