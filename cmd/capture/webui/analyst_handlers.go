package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/analyst"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gogo/protobuf/proto"
)

var analystSlots = make(chan struct{}, 2)

type analystSource = analyst.SourceSelection
type catalogueRequest = analyst.CatalogueRequest

func analystInput(w http.ResponseWriter, r *http.Request, value any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil || analyst.DecodeStrict(data, value) != nil {
		http.Error(w, "Invalid analyst request schema", 400)
		return false
	}
	return true
}
func analystFailure(w http.ResponseWriter, err error) {
	code := http.StatusUnprocessableEntity
	if errors.Is(err, analyst.ErrStale) {
		code = 409
	}
	if errors.Is(err, analyst.ErrBusy) {
		code = 429
	}
	if errors.Is(err, os.ErrNotExist) {
		code = 404
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = 408
	}
	http.Error(w, fmt.Sprintf("Analyst evidence request failed (%d); verify binding, input coverage and supported limits", code), code)
}
func analystContext(w http.ResponseWriter, r *http.Request) (context.Context, func(), bool) {
	select {
	case analystSlots <- struct{}{}:
	default:
		http.Error(w, "Analyst capacity busy", 429)
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	return ctx, func() { cancel(); <-analystSlots }, true
}
func (s *Server) analystSource(r *http.Request, src analystSource) (captureSelection, error) {
	if src.SessionID == "" && src.InputFile == "" {
		return captureSelection{}, selectionError(400, "Explicit analyst source inclusion required")
	}
	selected, err := s.resolveBodyCapture(r, src.InputFile, src.SessionID, src.Binding.RunID)
	if err != nil {
		return selected, err
	}
	if err = analyst.Check(r.Context(), selected.OutputDir, src.Binding); err != nil {
		return selected, err
	}
	return selected, nil
}

func (s *Server) handleAnalystCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	RespondJSON(w, 200, map[string]any{"version": 1, "occurrenceVersion": 1, "catalogueVersion": 1, "workspaceVersion": 1, "reviewedLogVersion": 1, "inspectionVersion": 1, "boundStreamVersion": 1, "maxSources": 8, "maxRecords": analyst.MaxRecords, "maxOccurrences": 4096, "maxSeconds": 30, "sourceInclusion": "explicit-only", "catalogueFields": analyst.CatalogueFields(), "catalogueKinds": []string{"sha256", "domain", "endpoint", "text"}, "boundStreamFilters": []string{"unfiltered", "communityId"}})
}
func (s *Server) handleAnalystBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !r.URL.Query().Has("inputFile") && !r.URL.Query().Has("sessionId") {
		http.Error(w, "Explicit capture required", 400)
		return
	}
	selected, ok := s.selectedCapture(w, r)
	if !ok {
		return
	}
	var b analyst.Binding
	var err error
	if r.URL.Query().Get("diagnostic") == "true" {
		b, err = analyst.BindDiagnostic(r.Context(), selected.OutputDir)
	} else {
		b, err = analyst.Bind(r.Context(), selected.OutputDir)
	}
	if err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, b)
}
func (s *Server) handleAnalystCatalogue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var body catalogueRequest
	if !analystInput(w, r, &body) {
		return
	}
	if len(body.Sources) < 1 || len(body.Sources) > 8 {
		http.Error(w, "Include 1–8 explicit captures", 400)
		return
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	r = r.WithContext(ctx)
	sources := make([]analyst.Source, 0, len(body.Sources))
	for _, src := range body.Sources {
		selected, err := s.analystSource(r, src)
		if err != nil {
			if typed, ok := err.(*captureSelectionError); ok {
				writeSelectionError(w, typed)
			} else {
				analystFailure(w, err)
			}
			return
		}
		sources = append(sources, analyst.Source{ID: src.Binding.RunID, Binding: src.Binding, Directory: selected.OutputDir})
	}
	result, err := analyst.Search(ctx, sources, body.Query)
	if err != nil {
		analystFailure(w, err)
		return
	}
	result, err = analyst.Paginate(result, body.Page, body.ExpectedSnapshotSHA256)
	if err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, result)
}
func (s *Server) handleAnalystOccurrence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var body struct {
		Source    analystSource     `json:"source"`
		Reference analyst.Reference `json:"reference"`
	}
	if !analystInput(w, r, &body) {
		return
	}
	if body.Source.Binding != body.Reference.Binding {
		http.Error(w, "Conflicting occurrence source", 409)
		return
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	r = r.WithContext(ctx)
	selected, err := s.analystSource(r, body.Source)
	if err != nil {
		if _, ok := err.(*captureSelectionError); ok {
			writeSelectionError(w, err)
		} else {
			analystFailure(w, err)
		}
		return
	}
	record, err := analyst.Resolve(ctx, selected.OutputDir, body.Reference)
	if err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, map[string]any{"version": 1, "reference": body.Reference, "record": record})
}
func (s *Server) handleAnalystOccurrences(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var body struct {
		Source analystSource `json:"source"`
		Type   string        `json:"type"`
	}
	if !analystInput(w, r, &body) {
		return
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	r = r.WithContext(ctx)
	selected, err := s.analystSource(r, body.Source)
	if err != nil {
		if _, ok := err.(*captureSelectionError); ok {
			writeSelectionError(w, err)
		} else {
			analystFailure(w, err)
		}
		return
	}
	refs := []analyst.Reference{}
	err = analyst.Walk(ctx, selected.OutputDir, body.Source.Binding, body.Type, func(ref analyst.Reference, _ proto.Message) error {
		if len(refs) >= 4096 {
			return fmt.Errorf("occurrence page limit exceeded; use catalogue query")
		}
		refs = append(refs, ref)
		return nil
	})
	if err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, map[string]any{"version": 1, "references": refs})
}
func (s *Server) handleAnalystWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var body struct {
		Source           analystSource     `json:"source"`
		Document         *analyst.Document `json:"document,omitempty"`
		ExpectedRevision int               `json:"expectedRevision"`
	}
	if !analystInput(w, r, &body) {
		return
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	r = r.WithContext(ctx)
	selected, err := s.analystSource(r, body.Source)
	if err != nil {
		if _, ok := err.(*captureSelectionError); ok {
			writeSelectionError(w, err)
		} else {
			analystFailure(w, err)
		}
		return
	}
	if !s.analystPrivateWorkspace(selected) {
		http.Error(w, "Public preloaded captures do not have a shared writable analyst workspace", 403)
		return
	}
	if body.Document != nil {
		release, ok := leaseOfflineMutation(selected.OutputDir)
		if !ok {
			http.Error(w, "Analysis output is busy", 429)
			return
		}
		defer release()
	}
	if body.Document == nil {
		workspace, e := analyst.LoadWorkspace(ctx, selected.OutputDir, body.Source.Binding)
		if e != nil {
			analystFailure(w, e)
			return
		}
		for _, doc := range workspace.Documents {
			for _, src := range doc.IncludedSources {
				if _, e = s.analystSource(r, src); e != nil {
					analystFailure(w, e)
					return
				}
			}
		}
		RespondJSON(w, 200, workspace)
		return
	}
	if len(body.Document.IncludedSources) > 8 {
		http.Error(w, "Too many document sources", 400)
		return
	}
	documentSources := []analyst.Source{}
	for _, src := range body.Document.IncludedSources {
		var included captureSelection
		if included, err = s.analystSource(r, src); err != nil {
			if _, ok := err.(*captureSelectionError); ok {
				writeSelectionError(w, err)
			} else {
				analystFailure(w, err)
			}
			return
		}
		documentSources = append(documentSources, analyst.Source{ID: src.Binding.RunID, Binding: src.Binding, Directory: included.OutputDir})
	}
	if body.Document.Kind == "query" {
		if body.Document.Query == nil {
			http.Error(w, "Saved query is required", 400)
			return
		}
		snapshot, e := analyst.Search(ctx, documentSources, *body.Document.Query)
		if e != nil {
			analystFailure(w, e)
			return
		}
		if snapshot.SnapshotSHA256 != body.Document.CatalogueSnapshotSHA256 {
			analystFailure(w, analyst.ErrStale)
			return
		}
	}
	doc, err := analyst.SaveDocument(ctx, selected.OutputDir, body.Source.Binding, *body.Document, body.ExpectedRevision)
	if err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, doc)
}

func (s *Server) analystPrivateWorkspace(selected captureSelection) bool {
	s.mu.RLock()
	service, manager := s.isServiceMode, s.sessionManager
	s.mu.RUnlock()
	if !service {
		return true
	}
	if manager == nil {
		return false
	}
	session, ok := manager.GetSession(selected.SessionID)
	return ok && !session.IsPreloaded
}

func (s *Server) handleAnalystLogReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var body struct {
		Source  analystSource      `json:"source"`
		File    string             `json:"file"`
		Start   int                `json:"start"`
		End     int                `json:"end"`
		Approve *analyst.LogReview `json:"approve,omitempty"`
	}
	if !analystInput(w, r, &body) {
		return
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	r = r.WithContext(ctx)
	if body.Source.SessionID == "" && body.Source.InputFile == "" {
		http.Error(w, "Explicit diagnostic capture required", 400)
		return
	}
	selected, err := s.resolveBodyCapture(r, body.Source.InputFile, body.Source.SessionID, body.Source.Binding.RunID)
	if err != nil {
		writeSelectionError(w, err)
		return
	}
	if err = analyst.CheckDiagnostic(ctx, selected.OutputDir, body.Source.Binding); err != nil {
		analystFailure(w, err)
		return
	}
	if body.Approve != nil {
		if body.Approve.File != body.File || body.Approve.Start != body.Start || body.Approve.End != body.End {
			http.Error(w, "Conflicting log review selection", 409)
			return
		}
		if !s.analystPrivateWorkspace(selected) {
			http.Error(w, "Public preloaded captures cannot store diagnostic reviews", 403)
			return
		}
		release, ok := leaseOfflineMutation(selected.OutputDir)
		if !ok {
			http.Error(w, "Analysis output is busy", 429)
			return
		}
		defer release()
		if body.Approve.Binding != body.Source.Binding {
			http.Error(w, "Conflicting review binding", 409)
			return
		}
		if err = analyst.ApproveLog(ctx, selected.OutputDir, *body.Approve); err != nil {
			analystFailure(w, err)
			return
		}
		RespondJSON(w, 200, map[string]any{"state": "reviewed"})
		return
	}
	review, err := analyst.PreviewLog(ctx, selected.OutputDir, body.Source.Binding, body.File, body.Start, body.End)
	if err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, review)
}

func (s *Server) handleAnalystInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var body struct {
		Source analystSource `json:"source"`
	}
	if !analystInput(w, r, &body) {
		return
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	r = r.WithContext(ctx)
	selected, err := s.analystSource(r, body.Source)
	if err != nil {
		if _, ok := err.(*captureSelectionError); ok {
			writeSelectionError(w, err)
		} else {
			analystFailure(w, err)
		}
		return
	}
	result, err := evidence.InspectCapture(ctx, selected.InputFile, 1000000, 1<<30)
	if err != nil {
		analystFailure(w, err)
		return
	}
	if result.SourceSHA256 != body.Source.Binding.SourceSHA256 {
		analystFailure(w, analyst.ErrStale)
		return
	}
	if err = analyst.Check(ctx, selected.OutputDir, body.Source.Binding); err != nil {
		analystFailure(w, err)
		return
	}
	RespondJSON(w, 200, result)
}
