// Package helpers provides utilities for testing Netcap components
package helpers

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gogo/protobuf/proto"
)

// TestFixture represents a test case with input PCAP and expected outputs
type TestFixture struct {
	Name         string
	PcapPath     string
	ExpectedType string
	PacketCount  int
	Golden       GoldenFiles
	Config       map[string]interface{}
}

// GoldenFiles contains paths to expected output files
type GoldenFiles struct {
	CSV      map[string]string // protocol -> csv file path
	JSON     map[string]string
	Protobuf map[string]string
}

// FixtureLoader handles loading test fixtures and golden files
type FixtureLoader struct {
	BaseDir string
}

// NewFixtureLoader creates a new fixture loader
func NewFixtureLoader(baseDir string) *FixtureLoader {
	return &FixtureLoader{
		BaseDir: baseDir,
	}
}

// LoadFixture loads a test fixture by name
func (fl *FixtureLoader) LoadFixture(name string) (*TestFixture, error) {
	fixturePath := filepath.Join(fl.BaseDir, "fixtures", name)

	// Check if fixture exists
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("fixture not found: %s", name)
	}

	// Load fixture configuration
	// TODO: Implement fixture config loading from YAML/JSON

	return &TestFixture{
		Name:     name,
		PcapPath: filepath.Join(fixturePath, "capture.pcap"),
	}, nil
}

// LoadPCAP loads a test PCAP file
func (fl *FixtureLoader) LoadPCAP(name string) (string, error) {
	pcapPath := filepath.Join(fl.BaseDir, "fixtures", "pcaps", name)

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		return "", fmt.Errorf("PCAP not found: %s", name)
	}

	return pcapPath, nil
}

// LoadGoldenFile loads a golden file for comparison
func (fl *FixtureLoader) LoadGoldenFile(protocol, format, scenario string) ([]byte, error) {
	goldenPath := filepath.Join(fl.BaseDir, "fixtures", "golden", format, scenario, fmt.Sprintf("%s.%s", protocol, format))

	data, err := os.ReadFile(goldenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read golden file %s: %w", goldenPath, err)
	}

	return data, nil
}

// SaveGoldenFile saves a golden file (for updating baselines)
func (fl *FixtureLoader) SaveGoldenFile(protocol, format, scenario string, data []byte) error {
	goldenDir := filepath.Join(fl.BaseDir, "fixtures", "golden", format, scenario)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(goldenDir, 0755); err != nil {
		return fmt.Errorf("failed to create golden directory: %w", err)
	}

	goldenPath := filepath.Join(goldenDir, fmt.Sprintf("%s.%s", protocol, format))

	if err := os.WriteFile(goldenPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write golden file: %w", err)
	}

	return nil
}

// CompareAuditRecords compares two audit records for equality
func CompareAuditRecords(t *testing.T, got, want proto.Message) {
	t.Helper()

	if !proto.Equal(got, want) {
		t.Errorf("audit records not equal\ngot:  %v\nwant: %v", got, want)
	}
}

// CompareCSV compares two CSV outputs
func CompareCSV(t *testing.T, got, want []byte) {
	t.Helper()

	if string(got) != string(want) {
		t.Errorf("CSV output differs\ngot:\n%s\nwant:\n%s", string(got), string(want))
	}
}

// CompareJSON compares two JSON outputs
func CompareJSON(t *testing.T, got, want []byte) {
	t.Helper()

	// TODO: Implement proper JSON comparison (ignoring whitespace differences)
	if string(got) != string(want) {
		t.Errorf("JSON output differs\ngot:\n%s\nwant:\n%s", string(got), string(want))
	}
}

// ShouldUpdateGolden returns true if golden files should be updated
func ShouldUpdateGolden() bool {
	return os.Getenv("UPDATE_GOLDEN") == "1"
}

// TestDataPath returns the path to test data directory
func TestDataPath() string {
	// Try to find tests directory
	if dir := os.Getenv("NETCAP_TEST_DATA"); dir != "" {
		return dir
	}

	// Default to relative path
	return "../tests"
}

// TempOutputDir creates a temporary directory for test outputs
func TempOutputDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
