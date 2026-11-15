package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/protocoltest"
)

func decodeProtocolRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		http.Error(w, err.Error(), 400)
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		http.Error(w, "expected one request", 400)
		return false
	}
	return true
}

func (s *Server) admitSourceAnalysis(w http.ResponseWriter, r *http.Request) func() {
	if err := r.Context().Err(); err != nil {
		http.Error(w, err.Error(), 408)
		return nil
	}
	s.mu.Lock()
	if s.sourceAnalysisSlots == nil {
		s.sourceAnalysisSlots = make(chan struct{}, 2)
	}
	slots := s.sourceAnalysisSlots
	s.mu.Unlock()
	select {
	case slots <- struct{}{}:
		return func() { <-slots }
	default:
		http.Error(w, "source analysis capacity reached", 503)
		return nil
	}
}

func boundDirectionalInput(ctx context.Context, out, id, direction, expected string) ([]byte, string, error) {
	if !strings.HasPrefix(id, "stream-") || filepath.Base(id) != id || strings.ContainsAny(id, "/\\\x00") || (direction != "client" && direction != "server") {
		return nil, "", fmt.Errorf("invalid directional stream selector")
	}
	base := filepath.Join("stream-evidence", id)
	raw, err := artifactio.Read(ctx, out, filepath.Join(base, "manifest.json"), 16<<20)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(raw)
	binding := hex.EncodeToString(digest[:])
	if expected == "" || expected != binding {
		return nil, "", fmt.Errorf("stream manifest SHA256 is required and must match")
	}
	var manifest streamutils.StreamEvidenceManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Version != 1 || manifest.Protocol != "TCP" || manifest.Status != "no-reported-gap" {
		return nil, "", fmt.Errorf("grammar requires TCP with no reported gaps, not partial or datagram evidence")
	}
	for _, span := range manifest.Spans {
		if span.MissingBytes != 0 || span.DiscardedBytes != 0 || span.Datagram {
			return nil, "", fmt.Errorf("refusing grammar interpretation across gaps/discards/datagrams")
		}
	}
	data, err := artifactio.Read(ctx, out, filepath.Join(base, direction+".bin"), 16<<20)
	if err != nil {
		return nil, "", err
	}
	file := manifest.Client
	if direction == "server" {
		file = manifest.Server
	}
	actual := sha256.Sum256(data)
	if file.Name != direction+".bin" || file.Length != int64(len(data)) || hex.EncodeToString(actual[:]) != file.SHA256 {
		return nil, "", fmt.Errorf("directional bytes do not match manifest")
	}
	return data, binding, nil
}

func (s *Server) handleInterpretStream(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID               string               `json:"id"`
		Direction        string               `json:"direction"`
		ManifestSHA256   string               `json:"manifestSHA256"`
		CompareID        string               `json:"compareId,omitempty"`
		CompareDirection string               `json:"compareDirection,omitempty"`
		CompareManifest  string               `json:"compareManifestSHA256,omitempty"`
		Grammar          protocoltest.Grammar `json:"grammar"`
	}
	if !decodeProtocolRequest(w, r, &request) {
		return
	}
	release := s.admitSourceAnalysis(w, r)
	if release == nil {
		return
	}
	defer release()
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return
	}
	data, binding, err := boundDirectionalInput(r.Context(), selected.OutputDir, request.ID, request.Direction, request.ManifestSHA256)
	if err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	var result any
	if request.CompareID != "" {
		other, _, readErr := boundDirectionalInput(r.Context(), selected.OutputDir, request.CompareID, request.CompareDirection, request.CompareManifest)
		if readErr != nil {
			http.Error(w, readErr.Error(), 422)
			return
		}
		result, err = request.Grammar.Compare(data, other)
	} else {
		result, err = request.Grammar.Interpret(data)
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	RespondJSON(w, 200, map[string]any{"report": result, "manifestSHA256": binding, "operation_error": message})
}

func (s *Server) handleTLSCapture(w http.ResponseWriter, r *http.Request) {
	if s.isServiceMode && !captureAdminAuthorized(r) {
		http.Error(w, "host secret-file access requires service administrator identity", 403)
		return
	}
	var request struct {
		KeyLog       string `json:"keyLog"`
		SourceSHA256 string `json:"sourceSHA256"`
		Stream       *int   `json:"stream,omitempty"`
		CommunityID  string `json:"communityId,omitempty"`
	}
	if !decodeProtocolRequest(w, r, &request) {
		return
	}
	release := s.admitSourceAnalysis(w, r)
	if release == nil {
		return
	}
	defer release()
	if (request.Stream != nil && (*request.Stream < 0 || request.CommunityID != "")) || !filepath.IsAbs(request.KeyLog) || len(request.SourceSHA256) != 64 {
		http.Error(w, "require absolute keyLog, sourceSHA256 and exclusive stream/communityId", 400)
		return
	}
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "netcap-tls-plaintext-")
	if err != nil {
		http.Error(w, "cannot allocate TLS snapshot", 500)
		return
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "input.pcap")
	hash, err := snapshotBoundedArtifact(ctx, filepath.Dir(selected.InputFile), filepath.Base(selected.InputFile), input, 256<<20)
	if err != nil || hash != request.SourceSHA256 {
		http.Error(w, "capture source changed", 409)
		return
	}
	keyPath := filepath.Join(dir, "secrets.log")
	if _, err := snapshotBoundedArtifact(ctx, filepath.Dir(request.KeyLog), filepath.Base(request.KeyLog), keyPath, 4<<20); err != nil {
		http.Error(w, "bounded regular TLS key log snapshot unavailable", 422)
		return
	}
	analyze := s.tlsAnalyzer
	if analyze == nil {
		analyze = protocoltest.AnalyzeTLSCapture
	}
	stream := 0
	if request.Stream != nil {
		stream = *request.Stream
	}
	if request.CommunityID != "" {
		stream, err = protocoltest.TLSStreamByCommunityID(ctx, input, request.CommunityID)
		if err != nil {
			http.Error(w, "TLS stream selection failed: "+err.Error(), 422)
			return
		}
	}
	result, err := analyze(ctx, input, keyPath, stream)
	message := ""
	if err != nil {
		message = err.Error()
	}
	message = strings.ReplaceAll(strings.ReplaceAll(message, keyPath, "[private key-log snapshot]"), input, "[private capture snapshot]")
	RespondJSON(w, 200, map[string]any{"report": result, "operation_error": message})
}
