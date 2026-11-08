package file

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/magika"
)

const AnalysisReportFile = "artifact-analysis.json"

var yaraBindingVersion = sync.OnceValue(func() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/VirusTotal/yara-x/go" {
				if dep.Replace != nil {
					return dep.Replace.Path + "@" + dep.Replace.Version
				}
				return dep.Path + "@" + dep.Version
			}
		}
	}
	return "YARA-X binding version unavailable (native library version not exposed)"
})

type AnalyzerResult struct {
	Version        string         `json:"version,omitempty"`
	Engine         string         `json:"engine"`
	State          string         `json:"state"`
	Outcome        string         `json:"outcome,omitempty"`
	Error          string         `json:"error,omitempty"`
	Digest         string         `json:"digest"`
	Matches        []string       `json:"matches,omitempty"`
	Classification *magika.Result `json:"classification,omitempty"`
}
type ArtifactAnalysis struct {
	SHA256       string           `json:"sha256"`
	ConfigDigest string           `json:"configDigest"`
	Analyzers    []AnalyzerResult `json:"analyzers"`
}
type AnalysisReport struct {
	ExecutedJobs     uint64                       `json:"executedJobs"`
	CacheHits        uint64                       `json:"cacheHits"`
	Analyzers        []AnalyzerResult             `json:"analyzers"`
	Version          int                          `json:"version"`
	RunID            string                       `json:"runId"`
	State            string                       `json:"state"`
	Error            string                       `json:"error,omitempty"`
	ConfigDigest     string                       `json:"configDigest"`
	Results          map[string]*ArtifactAnalysis `json:"results"`
	Rejected         uint64                       `json:"rejected"`
	ExtractionIssues []string                     `json:"extractionIssues,omitempty"`
}
type analysisEntry struct {
	result *ArtifactAnalysis
	done   chan struct{}
}
type analysisJob struct {
	entry *analysisEntry
	data  []byte
	size  int64
}
type analysisRuntime struct {
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	jobs             chan analysisJob
	directory        string
	cfg              *Config
	report           AnalysisReport
	cache            map[string]*analysisEntry
	cacheBytes       int
	queuedBytes      int64
	yara             yaraBackend
	magika           *magika.Classifier
	persistenceError error
}

type yaraBackend interface {
	Digest() string
	ScanBytesContext(context.Context, []byte) ([]string, error)
}

var analysisGlobal struct {
	sync.RWMutex
	runtime *analysisRuntime
}

func currentAnalysis() *analysisRuntime {
	analysisGlobal.RLock()
	defer analysisGlobal.RUnlock()
	return analysisGlobal.runtime
}

func BindAnalysisRunID(runID string) {
	if runID != "" {
		if m := currentAnalysis(); m != nil {
			m.mu.Lock()
			m.report.RunID = runID
			m.mu.Unlock()
		}
	}
}

// StartAnalysis freezes extraction policy and private analyzer snapshots for one capture.
func StartAnalysis(directory, runID string) error {
	cfg := GetGlobalConfig()
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	m := &analysisRuntime{directory: directory, cfg: cfg, jobs: make(chan analysisJob, 32), cache: map[string]*analysisEntry{}}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	a := cfg.FileExtraction.Advanced
	if cfg.FileExtraction.Enabled && a.EnableYaraScanning {
		if !YaraAvailable() {
			m.cancel()
			return fmt.Errorf("requested YARA support is not compiled in")
		}
		scanner, err := NewYaraScanner(a.YaraRulesPath)
		if err != nil {
			m.cancel()
			return err
		}
		if scanner.RuleCount() == 0 {
			m.cancel()
			return fmt.Errorf("requested YARA has no enabled rules")
		}
		m.yara = scanner
	}
	if cfg.FileExtraction.Enabled && a.EnableMagika {
		classifier, err := magika.NewClassifier()
		if err != nil {
			m.cancel()
			return fmt.Errorf("requested Magika: %w", err)
		}
		m.magika = classifier
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		m.cancel()
		return err
	}
	snapshot, _ := json.Marshal(cfg)
	h := sha256.Sum256(snapshot)
	// Bind analysis identity to exact engine/rules content as well as configuration.
	identity := hex.EncodeToString(h[:])
	if m.yara != nil {
		identity += m.yara.Digest() + yaraBindingVersion()
	}
	if m.magika != nil {
		identity += m.magika.Digest
	}
	digest := sha256.Sum256([]byte(identity))
	m.report = AnalysisReport{Version: 1, RunID: hex.EncodeToString(id[:]), State: "running", ConfigDigest: hex.EncodeToString(digest[:]), Results: map[string]*ArtifactAnalysis{}}
	if runID != "" {
		m.report.RunID = runID
	}
	m.report.Analyzers = []AnalyzerResult{{Engine: "yara-x", State: "disabled"}, {Engine: "magika", State: "disabled"}}
	if m.yara != nil {
		m.report.Analyzers[0].State = "ready"
		m.report.Analyzers[0].Digest = m.yara.Digest()
		m.report.Analyzers[0].Version = yaraBindingVersion()
	}
	if m.magika != nil {
		m.report.Analyzers[1].State = "ready"
		m.report.Analyzers[1].Digest = m.magika.Digest
		m.report.Analyzers[1].Version = "executable-sha256:" + m.magika.Digest
	}
	if err := m.persistLocked(); err != nil {
		m.cancel()
		return fmt.Errorf("persist artifact analysis admission: %w", err)
	}
	analysisGlobal.Lock()
	if analysisGlobal.runtime != nil {
		analysisGlobal.Unlock()
		m.cancel()
		return fmt.Errorf("artifact analysis capture already active")
	}
	analysisGlobal.runtime = m
	analysisGlobal.Unlock()
	configMutex.Lock()
	frozenConfig = cfg
	configMutex.Unlock()
	resetExtractionBudget(true)
	ResetDedupCache()
	for range 2 {
		m.wg.Add(1)
		go m.worker()
	}
	return nil
}

func (m *analysisRuntime) persistLocked() error {
	if m.directory == "" {
		return nil
	}
	root, err := os.OpenRoot(m.directory)
	if err != nil {
		return err
	}
	defer root.Close()
	b, err := json.Marshal(m.report)
	if err != nil {
		return err
	}
	if len(b) > 16<<20 {
		return fmt.Errorf("artifact result budget exceeded")
	}
	var id [8]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	name := ".analysis-" + hex.EncodeToString(id[:]) + ".tmp"
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, writeErr := f.Write(b)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	return root.Rename(name, AnalysisReportFile)
}

func (m *analysisRuntime) worker() {
	defer m.wg.Done()
	for job := range m.jobs {
		m.mu.Lock()
		m.report.ExecutedJobs++
		result := *job.entry.result
		result.Analyzers = append([]AnalyzerResult(nil), result.Analyzers...)
		for i := range job.entry.result.Analyzers {
			job.entry.result.Analyzers[i].State = "running"
		}
		if err := m.persistLocked(); err != nil {
			m.persistenceError = errors.Join(m.persistenceError, err)
		}
		m.mu.Unlock()
		ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
		for i := range result.Analyzers {
			r := &result.Analyzers[i]
			var err error
			switch r.Engine {
			case "yara-x":
				hash := sha256.Sum256(job.data)
				if hex.EncodeToString(hash[:]) != result.SHA256 {
					err = fmt.Errorf("artifact hash changed")
				} else {
					r.Matches, err = m.yara.ScanBytesContext(ctx, job.data)
				}
				if err == nil {
					r.Outcome = "no-match"
					if len(r.Matches) > 0 {
						r.Outcome = "matched"
					}
				}
			case "magika":
				r.Classification, err = m.magika.ClassifyBytes(ctx, job.data)
				if err == nil {
					r.Outcome = "classified"
				}
			}
			r.State = "completed"
			if err != nil {
				r.State = "failed"
				if errors.Is(err, context.Canceled) {
					r.State = "cancelled"
				}
				if errors.Is(err, context.DeadlineExceeded) {
					r.State = "timed-out"
				}
				r.Error = err.Error()
			}
		}
		cancel()
		m.mu.Lock()
		m.queuedBytes -= job.size
		job.entry.result = &result
		m.report.Results[result.SHA256] = &result
		encoded, _ := json.Marshal(result)
		m.cacheBytes += len(encoded)
		if err := m.persistLocked(); err != nil {
			m.persistenceError = errors.Join(m.persistenceError, err)
		}
		close(job.entry.done)
		m.mu.Unlock()
	}
}

func analyzeStored(path, digest string, data []byte) ([]string, *magika.Result) {
	m := currentAnalysis()
	if m == nil {
		return nil, nil
	}
	if m.yara == nil && m.magika == nil {
		return nil, nil
	}
	m.mu.Lock()
	entry := m.cache[digest]
	if entry != nil {
		m.report.CacheHits++
	}
	if entry == nil {
		info, err := os.Stat(path)
		if err != nil {
			m.report.Rejected++
			m.report.ExtractionIssues = appendIssue(m.report.ExtractionIssues, "analysis artifact unavailable")
			m.mu.Unlock()
			return nil, nil
		}
		result := &ArtifactAnalysis{SHA256: digest, ConfigDigest: m.report.ConfigDigest}
		if m.yara != nil {
			result.Analyzers = append(result.Analyzers, AnalyzerResult{Engine: "yara-x", State: "queued", Digest: m.yara.Digest(), Version: yaraBindingVersion()})
		}
		if m.magika != nil {
			result.Analyzers = append(result.Analyzers, AnalyzerResult{Engine: "magika", State: "queued", Digest: m.magika.Digest, Version: "executable-sha256:" + m.magika.Digest})
		}
		entry = &analysisEntry{result: result, done: make(chan struct{})}
		if len(m.cache) >= 1024 || m.cacheBytes >= 16<<20 || info.Size() > 256<<20-m.queuedBytes {
			m.report.Rejected++
			m.report.ExtractionIssues = appendIssue(m.report.ExtractionIssues, "analysis admission budget exceeded")
			m.mu.Unlock()
			return nil, nil
		}
		m.cache[digest] = entry
		m.report.Results[digest] = result
		m.queuedBytes += info.Size()
		select {
		case m.jobs <- analysisJob{entry, data, info.Size()}:
		default:
			delete(m.cache, digest)
			delete(m.report.Results, digest)
			m.queuedBytes -= info.Size()
			m.report.Rejected++
			m.report.ExtractionIssues = appendIssue(m.report.ExtractionIssues, "analysis queue full")
			m.mu.Unlock()
			return nil, nil
		}
	}
	m.mu.Unlock()
	<-entry.done
	var matches []string
	var classification *magika.Result
	for _, r := range entry.result.Analyzers {
		if r.Engine == "yara-x" {
			matches = r.Matches
		}
		if r.Engine == "magika" {
			classification = r.Classification
		}
	}
	return matches, classification
}

func appendIssue(issues []string, issue string) []string {
	if len(issue) > 1024 {
		issue = issue[:1024]
	}
	if len(issues) < 128 {
		return append(issues, issue)
	}
	return issues
}
func RecordExtractionIssue(err error) {
	if err == nil {
		return
	}
	if m := currentAnalysis(); m != nil {
		m.mu.Lock()
		m.report.ExtractionIssues = appendIssue(m.report.ExtractionIssues, err.Error())
		m.mu.Unlock()
	}
}

func RecordArtifactWriteError(err error) {
	if err == nil {
		return
	}
	if m := currentAnalysis(); m != nil {
		m.mu.Lock()
		m.persistenceError = errors.Join(m.persistenceError, err)
		m.report.ExtractionIssues = appendIssue(m.report.ExtractionIssues, "artifact output write failed")
		m.mu.Unlock()
	}
}
func CancelAnalysis() {
	if m := currentAnalysis(); m != nil {
		m.cancel()
	}
}

// FinishAnalysis drains accepted jobs and durably reports incomplete coverage.
func FinishAnalysis() (analysisErr, persistenceErr error) {
	m := currentAnalysis()
	if m == nil {
		return nil, nil
	}
	close(m.jobs)
	m.wg.Wait()
	m.cancel()
	m.mu.Lock()
	m.report.State = "complete"
	if m.persistenceError != nil {
		m.report.State = "partial"
		message := m.persistenceError.Error()
		if len(message) > 1024 {
			message = message[:1024]
		}
		m.report.Error = message
	}
	if m.report.Rejected > 0 || len(m.report.ExtractionIssues) > 0 {
		m.report.State = "partial"
	}
	for _, result := range m.report.Results {
		for _, r := range result.Analyzers {
			if r.State != "completed" {
				m.report.State = "partial"
			}
		}
	}
	if m.report.State == "partial" && (m.yara != nil || m.magika != nil) {
		analysisErr = fmt.Errorf("artifact processing incomplete; inspect %s", AnalysisReportFile)
	}
	persistenceErr = errors.Join(m.persistenceError, m.persistLocked())
	m.mu.Unlock()
	analysisGlobal.Lock()
	analysisGlobal.runtime = nil
	analysisGlobal.Unlock()
	configMutex.Lock()
	frozenConfig = nil
	configMutex.Unlock()
	resetExtractionBudget(false)
	return
}
