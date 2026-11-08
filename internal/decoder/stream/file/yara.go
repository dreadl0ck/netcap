//go:build !noyara

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package file

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/artifactio"
	"io/fs"
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
	digest   string
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
		return fmt.Errorf("YARA rules directory is empty")
	}
	if info, err := os.Stat(ys.rulesDir); err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("YARA rules path is not a directory")
	}

	compiler, err := yara.NewCompiler(yara.EnableIncludes(false))
	if err != nil {
		return err
	}
	defer compiler.Destroy()

	enabled := map[string]bool{}
	meta, err := artifactio.Read(context.Background(), ys.rulesDir, "yara-rules-meta.json", 1<<20)
	if err == nil {
		if err = json.Unmarshal(meta, &enabled); err != nil {
			return fmt.Errorf("YARA metadata: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	hash := sha256.New()
	ruleCount := 0
	var total int
	err = filepath.WalkDir(ys.rulesDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}
		rel, err := filepath.Rel(ys.rulesDir, path)
		if err != nil {
			return err
		}
		if value, ok := enabled[filepath.ToSlash(rel)]; ok && !value {
			return nil
		}
		if value, ok := enabled[rel]; ok && !value {
			return nil
		}
		data, err := artifactio.Read(context.Background(), ys.rulesDir, rel, 1<<20)
		if err != nil {
			return err
		}
		total += len(data)
		ruleCount++
		if ruleCount > 1024 || total > 16<<20 {
			return fmt.Errorf("YARA ruleset exceeds compilation budget")
		}
		if err := compiler.AddSource(string(data)); err != nil {
			return fmt.Errorf("compile %s: %w", rel, err)
		}
		fmt.Fprintf(hash, "%d:%s:%d:", len(rel), rel, len(data))
		hash.Write(data)
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
	ys.digest = hex.EncodeToString(hash.Sum(nil))

	ys.lastLoad = time.Now()

	return nil
}

// ScanBytes scans byte content against loaded YARA rules and returns matched rule identifiers.
func (ys *YaraScanner) ScanBytes(data []byte) ([]string, error) {
	return ys.ScanBytesContext(context.Background(), data)
}

func (ys *YaraScanner) Digest() string { ys.mu.RLock(); defer ys.mu.RUnlock(); return ys.digest }

func (ys *YaraScanner) ScanBytesContext(ctx context.Context, data []byte) ([]string, error) {
	ys.mu.RLock()
	defer ys.mu.RUnlock()

	if ys.rules == nil {
		return nil, fmt.Errorf("no enabled YARA rules")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	scanner := yara.NewScanner(ys.rules)
	defer scanner.Destroy()
	timeout := 60 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	scanner.SetTimeout(timeout)

	results, err := scanner.Scan(data)
	if err != nil {
		if errors.Is(err, yara.ErrTimeout) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(results.MatchingRules()) > 4096 {
		return nil, fmt.Errorf("YARA match result limit exceeded")
	}
	return extractMatchedRuleNames(results), nil
}

// ScanFile scans a file on disk against loaded YARA rules.
func (ys *YaraScanner) ScanFile(path string) ([]string, error) {
	data, err := artifactio.Read(context.Background(), filepath.Dir(path), filepath.Base(path), GetMaxFileSize())
	if err != nil {
		return nil, err
	}
	return ys.ScanBytes(data)
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
	compiler, err := yara.NewCompiler(yara.EnableIncludes(false))
	if err != nil {
		return err
	}
	defer compiler.Destroy()

	return compiler.AddSource(source)
}

// --- Global singleton ---

var (
	globalYaraScanner *YaraScanner
	yaraGlobalMu      sync.RWMutex
)

// InitGlobalYaraScanner initializes the global YARA scanner with the given rules directory.
// Safe to call multiple times; only the first call takes effect.
func InitGlobalYaraScanner(rulesDir string) (*YaraScanner, error) {
	yaraGlobalMu.Lock()
	defer yaraGlobalMu.Unlock()
	if globalYaraScanner != nil && globalYaraScanner.rulesDir == rulesDir {
		return globalYaraScanner, nil
	}
	scanner, err := NewYaraScanner(rulesDir)
	if err != nil {
		return nil, err
	}
	globalYaraScanner = scanner
	return scanner, nil
}

// GetGlobalYaraScanner returns the global YARA scanner, or nil if not initialized.
func GetGlobalYaraScanner() *YaraScanner {
	yaraGlobalMu.RLock()
	defer yaraGlobalMu.RUnlock()
	return globalYaraScanner
}

// ResetGlobalYaraScanner resets the singleton so it can be re-initialized (for testing or reconfiguration).
func ResetGlobalYaraScanner() {
	yaraGlobalMu.Lock()
	defer yaraGlobalMu.Unlock()
	globalYaraScanner = nil
}
