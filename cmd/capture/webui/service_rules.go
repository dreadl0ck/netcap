package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/rules"
	"gopkg.in/yaml.v2"
)

const rulePackProvenanceFile = "detection-rules.json"

func ruleDigest(value any) string {
	data, err := yaml.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type rulePackProvenance struct {
	SHA256   string `json:"sha256"`
	Source   string `json:"source"`
	Enabled  int    `json:"enabled"`
}

// An operator-managed pack is explicit and applies to exactly one embedded
// generation. Files exported by older WebUIs are never loaded by a service.
func loadServiceRules(folder string, embedded *rules.Config) (*rules.Config, error) {
	if os.Getenv("NC_SERVICE_RULES_MODE") != "operator" {
		return embedded, nil
	}
	path := filepath.Join(folder, "operator.pack.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pack struct {
		BaseSHA256 string `yaml:"base_sha256"`
		Custom []*rules.Rule `yaml:"custom"`
		Overrides []*rules.Rule `yaml:"overrides"`
	}
	if err := yaml.UnmarshalStrict(data, &pack); err != nil {
		return nil, fmt.Errorf("operator pack: %w", err)
	}
	embeddedNames := make(map[string]bool, len(embedded.Rules))
	for _, rule := range embedded.Rules {
		embeddedNames[rule.Name] = true
	}
	add := &rules.Config{}
	seen := make(map[string]bool)
	for _, rule := range append(pack.Custom, pack.Overrides...) {
		if rule == nil || rule.Name == "" || seen[rule.Name] {
			return nil, fmt.Errorf("operator pack contains an empty or duplicate rule")
		}
		seen[rule.Name] = true
	}
	for _, rule := range pack.Custom {
		if embeddedNames[rule.Name] {
			return nil, fmt.Errorf("custom rule %q collides with a shipped rule", rule.Name)
		}
		add.Rules = append(add.Rules, rule)
	}
	for _, rule := range pack.Overrides {
		if !embeddedNames[rule.Name] || pack.BaseSHA256 != ruleDigest(embedded) {
			log.Printf("[Service] Ignoring retired or stale override %q", rule.Name)
			continue
		}
		add.Rules = append(add.Rules, rule)
	}
	return rules.MergeConfigs(embedded, add), nil
}
