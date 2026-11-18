package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/rules"
)

type jobSettings struct {
	Version          int               `json:"version"`
	Runtime          RuntimeConfig     `json:"runtime"`
	DPI              bool              `json:"dpi"`
	Payload          bool              `json:"payload"`
	NetworkDetection bool              `json:"networkDetection"`
	DNSContext       bool              `json:"dnsResolutionContext"`
	BPF              string            `json:"bpf"`
	IncludeDecoders  string            `json:"includeDecoders"`
	ExcludeDecoders  string            `json:"excludeDecoders"`
	Protobuf         protobufSettings  `json:"protobuf"`
	SchemaPaths      []string          `json:"requestedSchemaPaths"`
	SchemaHashes     map[string]string `json:"schemaHashes,omitempty"`
	Rules            *rules.Config     `json:"rules,omitempty"`
	cleanupOnce      sync.Once
	directory        string
}

func (s *Server) snapshotJobSettings() (*jobSettings, error) {
	select {
	case <-s.shutdownChan:
		return nil, errAnalysisStopping
	default:
	}
	s.mu.RLock()
	snapshot := &jobSettings{Version: 1, Runtime: s.runtimeSnapshotLocked(), DPI: s.dpiConfigured, Payload: s.payloadCapture}
	s.mu.RUnlock()
	config, err := s.loadRulesConfig()
	if err != nil {
		return nil, fmt.Errorf("snapshot detection rules: %w", err)
	}
	snapshot.Rules = config
	snapshot.NetworkDetection = s.featureEnabled(featureNetworkDetection)
	snapshot.DNSContext = s.featureEnabled(featureDNSResolutionContext)
	snapshot.Protobuf = currentProtobufSettings()
	snapshot.SchemaPaths = append([]string{}, snapshot.Protobuf.Paths...)
	// Preserve startup defaults before an in-process job installs private paths.
	protoRuntime.mu.Lock()
	if protoRuntime.searchPaths == nil {
		protoRuntime.searchPaths = append([]string{}, snapshot.Protobuf.Paths...)
	}
	if protoRuntime.mappings == nil {
		protoRuntime.mappings = append([]string{}, snapshot.Protobuf.Mappings...)
	}
	if protoRuntime.alternatives == nil {
		value := snapshot.Protobuf.Alternatives
		protoRuntime.alternatives = &value
	}
	protoRuntime.mu.Unlock()
	if len(snapshot.SchemaPaths) == 0 || s.shutdownChan == nil {
		return snapshotSchemaSources(snapshot)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go func() {
		select {
		case <-s.shutdownChan:
			cancel(errAnalysisStopping)
		case <-ctx.Done():
		}
	}()
	return snapshotSchemaSourcesContext(ctx, snapshot)
}

func snapshotSchemaSources(snapshot *jobSettings) (*jobSettings, error) {
	return snapshotSchemaSourcesContext(context.Background(), snapshot)
}

func snapshotSchemaSourcesContext(parent context.Context, snapshot *jobSettings) (*jobSettings, error) {
	if err := context.Cause(parent); err != nil {
		return nil, err
	}
	if len(snapshot.SchemaPaths) == 0 {
		return snapshot, nil
	}
	if len(snapshot.SchemaPaths) > 32 {
		return nil, fmt.Errorf("at most 32 Protobuf search roots")
	}
	dir, err := os.MkdirTemp("", "netcap-proto-job-")
	if err != nil {
		return nil, err
	}
	snapshot.directory = dir
	success := false
	defer func() {
		if !success {
			snapshot.cleanup()
		}
	}()
	if strings.Contains(dir, ",") {
		return nil, fmt.Errorf("Protobuf helper snapshot requires a TMPDIR without commas")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	files, remainingEntries, total := 0, 10000, 0
	snapshot.SchemaHashes = map[string]string{}
	snapshot.Protobuf.Paths = nil
	for index, path := range snapshot.SchemaPaths {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("schema roots must not be symlinks")
		}
		root := path
		single := ""
		if !info.IsDir() {
			root = filepath.Dir(path)
			single = filepath.Base(path)
		}
		target := filepath.Join(dir, fmt.Sprintf("root-%d", index))
		if err := os.Mkdir(target, 0700); err != nil {
			return nil, err
		}
		copyFile := func(relative string) error {
			files++
			if files > 256 {
				return fmt.Errorf("Protobuf snapshot exceeds 256 files")
			}
			data, err := artifactio.Read(ctx, root, relative, 2<<20)
			if err != nil {
				if cause := context.Cause(ctx); cause != nil {
					return cause
				}
				return err
			}
			total += len(data)
			if total > 16<<20 {
				return fmt.Errorf("Protobuf snapshot exceeds 16 MiB")
			}
			out := filepath.Join(target, relative)
			if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(out, data, 0600); err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			snapshot.SchemaHashes[filepath.Join(root, relative)] = hex.EncodeToString(digest[:])
			return nil
		}
		if single != "" {
			if err := copyFile(single); err != nil {
				return nil, err
			}
		} else {
			err := walkSchemaRoot(ctx, root, &remainingEntries, copyFile)
			if err != nil {
				return nil, err
			}
		}
		snapshot.Protobuf.Paths = append(snapshot.Protobuf.Paths, target)
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if files == 0 {
		return nil, fmt.Errorf("no schema files in configured Protobuf roots")
	}
	success = true
	return snapshot, nil
}

func walkSchemaRoot(ctx context.Context, path string, remaining *int, copyFile func(string) error) error {
	(*remaining)-- // Count the root as well as its children.
	if *remaining < 0 {
		return fmt.Errorf("Protobuf snapshot exceeds 10000 directory entries")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		entries, err := readSchemaDirectory(ctx, root, dir, remaining)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			if depth == 16 {
				return fmt.Errorf("Protobuf snapshot nesting exceeds 16")
			}
			name := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				if err := walk(name, depth+1); err != nil {
					return err
				}
			} else if strings.HasSuffix(entry.Name(), ".proto") {
				if err := copyFile(name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(".", 0)
}

func readSchemaDirectory(ctx context.Context, root *os.Root, dir string, remaining *int) ([]os.DirEntry, error) {
	f, err := root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []os.DirEntry
	for {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		batch, err := f.ReadDir(min(256, *remaining+1))
		*remaining -= len(batch)
		if *remaining < 0 {
			return nil, fmt.Errorf("Protobuf snapshot exceeds 10000 directory entries")
		}
		entries = append(entries, batch...)
		if err == io.EOF {
			slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (snapshot *jobSettings) cleanup() {
	if snapshot != nil {
		snapshot.cleanupOnce.Do(func() {
			if snapshot.directory != "" {
				_ = os.RemoveAll(snapshot.directory)
			}
		})
	}
}

func (s *Server) settingsForJob(job *AnalysisJob) (*jobSettings, error) {
	if job.settings == nil {
		snapshot, err := s.snapshotJobSettings()
		if err != nil {
			return nil, err
		}
		snapshot.DPI = job.EnableDPI
		snapshot.BPF = job.BPFFilter
		snapshot.IncludeDecoders = job.IncludeDecoders
		snapshot.ExcludeDecoders = job.ExcludeDecoders
		job.settings = snapshot
	}
	if job.requireCaptureEvidence {
		job.settings.Runtime.CaptureEvidence = true
	}
	if job.OutputDir != "" {
		if err := os.MkdirAll(job.OutputDir, 0755); err != nil {
			return nil, err
		}
		data, err := json.Marshal(job.settings)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(job.OutputDir, "analysis-runtime.json"), data, 0600); err != nil {
			return nil, err
		}
	}
	return job.settings, nil
}
