package webui

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"gopkg.in/yaml.v2"
	"path/filepath"
)

func snapshotArtifactConfig() ([]byte, error) {
	cfg := file.GetGlobalConfig()
	if err := file.ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if path := cfg.FileExtraction.Advanced.YaraRulesPath; path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		cfg.FileExtraction.Advanced.YaraRulesPath = absolute
	}
	return yaml.Marshal(cfg)
}

func applyArtifactJobConfig(job *AnalysisJob) (func(), error) {
	if len(job.ArtifactConfig) == 0 {
		return func() {}, nil
	}
	cfg := file.GetDefaultConfig()
	if err := yaml.UnmarshalStrict(job.ArtifactConfig, cfg); err != nil {
		return nil, err
	}
	if err := file.ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("artifact job configuration: %w", err)
	}
	old := file.GetGlobalConfig()
	file.SetGlobalConfig(cfg)
	return func() { file.SetGlobalConfig(old) }, nil
}
