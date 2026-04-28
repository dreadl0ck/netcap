//go:build !noyara

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package file

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	yara "github.com/VirusTotal/yara-x/go"
)

// YaraScanner provides thread-safe YARA rule scanning using yara-x.
type YaraScanner struct {
	mu       sync.RWMutex
	rules    *yara.Rules
	rulesDir string
	lastLoad time.Time
}

// NewYaraScanner creates a scanner by compiling all .yar/.yara files from rulesDir.
func NewYaraScanner(rulesDir string) (*YaraScanner, error) {
	ys := &YaraScanner{
		rulesDir: rulesDir,
	}

	if err := ys.Reload(); err != nil {
		return nil, err
	}

	return ys, nil
}

// Reload recompiles all enabled YARA rules from the rules directory.
func (ys *YaraScanner) Reload() error {
	ys.mu.Lock()
	defer ys.mu.Unlock()

	if ys.rulesDir == "" {
		return nil
	}

	// Check directory exists
	if _, err := os.Stat(ys.rulesDir); os.IsNotExist(err) {
		return nil
	}

	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}

	ruleCount := 0

	err = filepath.Walk(ys.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[YARA] Failed to read rule file %s: %v", path, err)
			return nil
		}

		if err := compiler.AddSource(string(data)); err != nil {
			log.Printf("[YARA] Failed to compile rule file %s: %v", path, err)
			return nil
		}

		ruleCount++

		return nil
	})
	if err != nil {
		return err
	}

	if ruleCount > 0 {
		ys.rules = compiler.Build()
		log.Printf("[YARA] Compiled %d rule file(s) from %s", ruleCount, ys.rulesDir)
	} else {
		ys.rules = nil
	}

	ys.lastLoad = time.Now()

	return nil
}

// ScanBytes scans byte content against loaded YARA rules and returns matched rule identifiers.
func (ys *YaraScanner) ScanBytes(data []byte) ([]string, error) {
	ys.mu.RLock()
	defer ys.mu.RUnlock()

	if ys.rules == nil {
		return nil, nil
	}

	scanner := yara.NewScanner(ys.rules)
	scanner.SetTimeout(60 * time.Second)

	results, err := scanner.Scan(data)
	if err != nil {
		return nil, err
	}

	return extractMatchedRuleNames(results), nil
}

// ScanFile scans a file on disk against loaded YARA rules.
func (ys *YaraScanner) ScanFile(path string) ([]string, error) {
	ys.mu.RLock()
	defer ys.mu.RUnlock()

	if ys.rules == nil {
		return nil, nil
	}

	scanner := yara.NewScanner(ys.rules)
	scanner.SetTimeout(60 * time.Second)

	results, err := scanner.ScanFile(path)
	if err != nil {
		return nil, err
	}

	return extractMatchedRuleNames(results), nil
}

// RulesDir returns the configured rules directory.
func (ys *YaraScanner) RulesDir() string {
	return ys.rulesDir
}

// RuleCount returns the number of compiled rules, or 0 if none loaded.
func (ys *YaraScanner) RuleCount() int {
	ys.mu.RLock()
	defer ys.mu.RUnlock()

	if ys.rules == nil {
		return 0
	}

	return ys.rules.Count()
}

// LastLoad returns the time the rules were last compiled.
func (ys *YaraScanner) LastLoad() time.Time {
	ys.mu.RLock()
	defer ys.mu.RUnlock()
	return ys.lastLoad
}

func extractMatchedRuleNames(results *yara.ScanResults) []string {
	matched := results.MatchingRules()
	if len(matched) == 0 {
		return nil
	}

	names := make([]string, 0, len(matched))
	for _, rule := range matched {
		names = append(names, rule.Identifier())
	}

	return names
}

// YaraAvailable returns true when yara-x support is compiled in.
func YaraAvailable() bool { return true }

// ValidateYaraSource compiles YARA source to check for errors.
// Returns nil if valid, or the compilation error.
func ValidateYaraSource(source string) error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}

	return compiler.AddSource(source)
}

// --- Global singleton ---

var (
	globalYaraScanner *YaraScanner
	yaraScannerOnce   sync.Once
	yaraScannerErr    error
)

// InitGlobalYaraScanner initializes the global YARA scanner with the given rules directory.
// Safe to call multiple times; only the first call takes effect.
func InitGlobalYaraScanner(rulesDir string) (*YaraScanner, error) {
	yaraScannerOnce.Do(func() {
		globalYaraScanner, yaraScannerErr = NewYaraScanner(rulesDir)
	})
	return globalYaraScanner, yaraScannerErr
}

// GetGlobalYaraScanner returns the global YARA scanner, or nil if not initialized.
func GetGlobalYaraScanner() *YaraScanner {
	return globalYaraScanner
}

// ResetGlobalYaraScanner resets the singleton so it can be re-initialized (for testing or reconfiguration).
func ResetGlobalYaraScanner() {
	globalYaraScanner = nil
	yaraScannerOnce = sync.Once{}
	yaraScannerErr = nil
}
