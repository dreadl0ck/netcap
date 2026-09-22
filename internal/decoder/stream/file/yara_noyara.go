//go:build noyara

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package file

import "time"

// YaraScanner is a no-op stub when built with the noyara tag.
type YaraScanner struct{}

// NewYaraScanner returns a no-op scanner.
func NewYaraScanner(rulesDir string) (*YaraScanner, error) { return &YaraScanner{}, nil }

// Reload is a no-op.
func (ys *YaraScanner) Reload() error { return nil }

// ScanBytes returns no matches.
func (ys *YaraScanner) ScanBytes(data []byte) ([]string, error) { return nil, nil }

// ScanFile returns no matches.
func (ys *YaraScanner) ScanFile(path string) ([]string, error) { return nil, nil }

// RulesDir returns empty string.
func (ys *YaraScanner) RulesDir() string { return "" }

// RuleCount returns 0.
func (ys *YaraScanner) RuleCount() int { return 0 }

// LastLoad returns zero time.
func (ys *YaraScanner) LastLoad() time.Time { return time.Time{} }

// YaraAvailable returns false when built without yara-x support.
func YaraAvailable() bool { return false }

// ValidateYaraSource is a no-op stub.
func ValidateYaraSource(source string) error { return nil }

// InitGlobalYaraScanner is a no-op.
func InitGlobalYaraScanner(rulesDir string) (*YaraScanner, error) { return &YaraScanner{}, nil }

// GetGlobalYaraScanner returns nil.
func GetGlobalYaraScanner() *YaraScanner { return nil }

// ResetGlobalYaraScanner is a no-op.
func ResetGlobalYaraScanner() {}
