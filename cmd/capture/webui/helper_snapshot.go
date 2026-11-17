package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	return snapshotSchemaSources(snapshot)
}

func snapshotSchemaSources(snapshot *jobSettings) (*jobSettings, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	files, entries, total := 0, 0, 0
	snapshot.SchemaHashes = map[string]string{}
	snapshot.Protobuf.Paths = nil
	for index, path := range snapshot.SchemaPaths {
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
			err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				entries++
				if entries > 10000 {
					return fmt.Errorf("Protobuf snapshot exceeds 10000 directory entries")
				}
				relative, err := filepath.Rel(root, name)
				if err != nil {
					return err
				}
				if len(strings.Split(filepath.ToSlash(relative), "/")) > 16 {
					return fmt.Errorf("Protobuf snapshot nesting exceeds 16")
				}
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".proto") {
					return nil
				}
				return copyFile(relative)
			})
			if err != nil {
				return nil, err
			}
		}
		snapshot.Protobuf.Paths = append(snapshot.Protobuf.Paths, target)
	}
	if files == 0 {
		return nil, fmt.Errorf("no schema files in configured Protobuf roots")
	}
	success = true
	return snapshot, nil
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
