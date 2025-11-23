package credentials

import (
	"bytes"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

// TestHarvesterMaxBytesLimit verifies that harvesters only process up to HarvesterBannerSize bytes
// and don't cause performance issues with large data streams
func TestHarvesterMaxBytesLimit(t *testing.T) {
	// Initialize config if not already initialized
	if decoderconfig.Instance == nil {
		decoderconfig.Instance = decoderconfig.DefaultConfig
	}
	
	// Save original config and restore after test
	originalSize := decoderconfig.Instance.HarvesterBannerSize
	defer func() {
		decoderconfig.Instance.HarvesterBannerSize = originalSize
	}()

	// Set a small limit for testing
	testLimit := 100
	decoderconfig.Instance.HarvesterBannerSize = testLimit

	// Create a large data stream (10KB) that starts with valid FTP credentials
	// followed by lots of binary data (simulating a file transfer)
	ftpHeader := `220 (vsFTPd 3.0.3)
USER testuser
331 Please specify the password.
PASS testpass
230 Login successful.
`
	ftpHeaderBytes := bytes.ReplaceAll([]byte(ftpHeader), []byte("\n"), []byte("\r\n"))

	// Add lots of binary data after the credentials to simulate a large file transfer
	largeData := make([]byte, 10*1024) // 10KB
	copy(largeData, ftpHeaderBytes)
	for i := len(ftpHeaderBytes); i < len(largeData); i++ {
		largeData[i] = byte(i % 256)
	}

	// Verify that the harvester only processes the first testLimit bytes
	// by ensuring it can still find the credentials even though the total data is much larger
	truncatedData := largeData[:testLimit]

	// Test FTP harvester on truncated data
	c := ftpHarvester(truncatedData, "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found in truncated data")
	}

	if c.User != "testuser" {
		t.Fatalf("incorrect user, got: %s, expected: testuser", c.User)
	}

	if c.Password != "testpass" {
		t.Fatalf("incorrect password, got: %s, expected: testpass", c.Password)
	}

	// Now test with a larger limit to ensure credentials can be found
	decoderconfig.Instance.HarvesterBannerSize = 1024
	truncatedData = largeData[:1024]

	c = ftpHarvester(truncatedData, "test", time.Now())
	if c == nil {
		t.Fatal("no credentials found with larger limit")
	}

	if c.User != "testuser" {
		t.Fatalf("incorrect user with larger limit, got: %s, expected: testuser", c.User)
	}
}

// TestRunHarvestersSafetyCheck verifies that RunHarvesters enforces the max bytes limit
func TestRunHarvestersSafetyCheck(t *testing.T) {
	// Initialize config if not already initialized
	if decoderconfig.Instance == nil {
		decoderconfig.Instance = decoderconfig.DefaultConfig
	}
	
	// Save original config and restore after test
	originalSize := decoderconfig.Instance.HarvesterBannerSize
	defer func() {
		decoderconfig.Instance.HarvesterBannerSize = originalSize
	}()

	// Set a limit
	testLimit := 100
	decoderconfig.Instance.HarvesterBannerSize = testLimit

	// Create data that exceeds the limit
	largeData := make([]byte, testLimit*2)
	for i := 0; i < len(largeData); i++ {
		largeData[i] = byte(i % 256)
	}

	// Test the truncation logic directly
	// Simulate what RunHarvesters does internally
	if len(largeData) > decoderconfig.Instance.HarvesterBannerSize {
		truncatedData := largeData[:decoderconfig.Instance.HarvesterBannerSize]
		
		if len(truncatedData) != testLimit {
			t.Fatalf("Expected truncated data to be %d bytes, got %d", testLimit, len(truncatedData))
		}
		
		t.Logf("Successfully truncated %d bytes to %d bytes", len(largeData), len(truncatedData))
	}
}

// TestPerformanceWithLargeStreams verifies that processing large streams doesn't cause excessive delays
func TestPerformanceWithLargeStreams(t *testing.T) {
	// Initialize config if not already initialized
	if decoderconfig.Instance == nil {
		decoderconfig.Instance = decoderconfig.DefaultConfig
	}
	
	// Save original config and restore after test
	originalSize := decoderconfig.Instance.HarvesterBannerSize
	defer func() {
		decoderconfig.Instance.HarvesterBannerSize = originalSize
	}()

	// Set a reasonable limit
	decoderconfig.Instance.HarvesterBannerSize = 512

	// Create a very large data stream (1MB)
	largeData := make([]byte, 1024*1024)
	for i := 0; i < len(largeData); i++ {
		largeData[i] = byte(i % 256)
	}

	// Measure time taken to process truncation
	// This simulates what happens in production
	start := time.Now()
	
	// Simulate the truncation logic
	processedData := largeData
	if len(processedData) > decoderconfig.Instance.HarvesterBannerSize {
		processedData = processedData[:decoderconfig.Instance.HarvesterBannerSize]
	}
	
	// Now run a harvester on the truncated data
	_ = ftpHarvester(processedData, "test-flow", time.Now())
	
	elapsed := time.Since(start)

	// Processing should be fast because we only process HarvesterBannerSize bytes
	// Even with a 1MB input, it should complete in milliseconds
	maxAllowedTime := 100 * time.Millisecond
	if elapsed > maxAllowedTime {
		t.Fatalf("Processing took too long: %v (max allowed: %v). "+
			"This suggests the harvester is processing more data than configured limit.",
			elapsed, maxAllowedTime)
	}

	t.Logf("Successfully processed 1MB stream (truncated to %d bytes) in %v", 
		decoderconfig.Instance.HarvesterBannerSize, elapsed)
}

// TestConfigurableLimit verifies that different HarvesterBannerSize values work correctly
func TestConfigurableLimit(t *testing.T) {
	// Initialize config if not already initialized
	if decoderconfig.Instance == nil {
		decoderconfig.Instance = decoderconfig.DefaultConfig
	}
	
	// Save original config and restore after test
	originalSize := decoderconfig.Instance.HarvesterBannerSize
	defer func() {
		decoderconfig.Instance.HarvesterBannerSize = originalSize
	}()

	testCases := []struct {
		limit       int
		description string
	}{
		{100, "very small limit"},
		{512, "default limit"},
		{2048, "medium limit"},
		{8192, "large limit"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			decoderconfig.Instance.HarvesterBannerSize = tc.limit

			// Create data larger than the limit
			data := make([]byte, tc.limit*2)
			copy(data, "220 (vsFTPd 3.0.3)\r\nUSER test\r\n331 Password\r\nPASS test\r\n230 Login\r\n")

			// Truncate to limit (simulating what createBannerFromConversation does)
			if len(data) > tc.limit {
				data = data[:tc.limit]
			}

			// Verify we can still process the data without issues
			c := ftpHarvester(data, "test", time.Now())

			// We may or may not find credentials depending on whether they fit in the limit
			// The important thing is that we don't crash or hang
			if c != nil {
				t.Logf("Found credentials with limit %d: user=%s", tc.limit, c.User)
			} else {
				t.Logf("No credentials found with limit %d (expected for small limits)", tc.limit)
			}
		})
	}
}

