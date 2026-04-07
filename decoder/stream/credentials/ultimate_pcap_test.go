/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package credentials_test

import (
	"os"
	"context"
	"os/exec"
	"time"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// TestUltimatePCAPFalsePositives builds and runs the netcap binary on
// "The Ultimate PCAP v20260316.pcapng" with the full engine (TCP reassembly,
// all decoders), then reads the Credentials audit records and validates that
// false positives are eliminated and valid credentials are found.
//
// Verified PCAP contents (via tshark):
//   - FTP: anonymous / User@, ftp1119456-nureintest / 98fDMjEHP6kV0D62WhK1
//   - SNMP: communities "public", "n5rAD1ig314IqfioYBWw", "password1234"
//   - Telnet: telnetuser / L35jFNz0Z4Ao8X6x4Uic
//   - RADIUS: bob with encrypted password and CHAP password
func TestUltimatePCAPFalsePositives(t *testing.T) {
	repoRoot, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	pcapFile := filepath.Join(repoRoot, "tests", "The Ultimate PCAP v20260316.pcapng")
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("The Ultimate PCAP v20260316.pcapng not found in tests/")
	}

	// Build the netcap binary from the repo root
	binaryPath := filepath.Join(t.TempDir(), "netcap-test")
	buildCmd := exec.Command("go", "build", "-tags=nodpi", "-o", binaryPath, "./cmd/")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build netcap binary: %v\n%s", err, out)
	}

	// Run netcap capture on the PCAP
	outDir := filepath.Join(t.TempDir(), "output")
	os.MkdirAll(outDir, 0o700)

	// Run with a 2-minute timeout. The PCAP processes in ~25s but cleanup
	// can hang on open TCP streams. The credentials are written before cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	captureCmd := exec.CommandContext(ctx, binaryPath, "capture",
		"-read", pcapFile,
		"-out", outDir,
		"-quiet",
	)
	captureCmd.Dir = repoRoot

	t.Log("Running netcap capture on The Ultimate PCAP v20260316.pcapng...")
	out, err := captureCmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Log("Capture timed out during cleanup (credentials already written)")
	} else if err != nil {
		t.Logf("Capture finished with: %v\nOutput: %s", err, string(out))
	}
	t.Log("Capture complete.")

	// Read back the Credentials audit records
	credFile := filepath.Join(outDir, "Credentials.ncap.gz")
	if _, err := os.Stat(credFile); os.IsNotExist(err) {
		t.Fatal("Credentials.ncap.gz not found — credentials decoder did not produce output")
	}

	reader, err := netio.Open(credFile, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open credentials file: %v", err)
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	type credRecord struct {
		Service, User, Password, Notes, Flow string
	}

	var allCreds []credRecord
	for {
		var cred types.Credentials
		if err := reader.Next(&cred); err != nil {
			break
		}
		allCreds = append(allCreds, credRecord{
			Service:  cred.Service,
			User:     cred.User,
			Password: cred.Password,
			Notes:    cred.Notes,
			Flow:     cred.Flow,
		})
	}

	t.Logf("Found %d credential records", len(allCreds))

	// Log all findings grouped by service
	byService := make(map[string][]credRecord)
	for _, c := range allCreds {
		byService[c.Service] = append(byService[c.Service], c)
	}
	var services []string
	for svc := range byService {
		services = append(services, svc)
	}
	sort.Strings(services)

	t.Log("\n=== All Findings ===")
	for _, svc := range services {
		for _, c := range byService[svc] {
			pass := c.Password
			if len(pass) > 50 {
				pass = pass[:50] + "..."
			}
			t.Logf("  [%s] User=%q Password=%q Flow=%s", svc, c.User, pass, c.Flow)
		}
	}

	// === FALSE POSITIVES ===
	t.Log("\n=== Checking False Positives ===")
	fpCount := 0
	for _, c := range allCreds {
		switch {
		case c.Service == "TeamViewer" && (c.User == "PING" || c.User == "KEEPALIVE_BEEP" || c.User == "PING_OK"):
			t.Errorf("FP: TeamViewer %s", c.User)
			fpCount++
		case c.Service == "mDNS":
			t.Errorf("FP: mDNS %q", c.User)
			fpCount++
		case c.Service == "UPnP":
			t.Errorf("FP: UPnP %q", c.User)
			fpCount++
		case c.Service == "NBNS":
			t.Errorf("FP: NBNS %q", c.User)
			fpCount++
		case c.Service == "WSD":
			t.Errorf("FP: WSD %q", c.User)
			fpCount++
		case c.Service == "Redis" && strings.EqualFold(c.Password, "TLS"):
			t.Errorf("FP: Redis password 'TLS'")
			fpCount++
		case c.Service == "RADIUS" && c.Password == "":
			t.Errorf("FP: RADIUS user %q with no password", c.User)
			fpCount++
		}
	}
	if fpCount == 0 {
		t.Log("  No false positives detected")
	}

	// === VALID CREDENTIALS ===
	t.Log("\n=== Checking Valid Credentials ===")
	expected := []struct {
		service, user, passwordSub, desc string
	}{
		{"Telnet", "telnetuser", "L35jFNz0Z4Ao8X6x4Uic", "Telnet login"},
		{"FTP", "anonymous", "User@", "FTP anonymous login"},
		{"FTP", "ftp1119456-nureintest", "98fDMjEHP6kV0D62WhK1", "FTP authenticated login"},
		{"SNMP", "", "public", "SNMP community 'public'"},
		{"SNMP", "", "n5rAD1ig314IqfioYBWw", "SNMP community 'n5rAD1ig314IqfioYBWw'"},
		{"RADIUS", "bob", "<encrypted:", "RADIUS encrypted password"},
		{"RADIUS", "bob", "<CHAP:", "RADIUS CHAP password"},
	}

	foundCount := 0
	for _, ev := range expected {
		found := false
		for _, c := range allCreds {
			if c.Service == ev.service && c.User == ev.user && strings.Contains(c.Password, ev.passwordSub) {
				found = true
				break
			}
		}
		if found {
			t.Logf("  FOUND: [%s] %s", ev.service, ev.desc)
			foundCount++
		} else {
			t.Errorf("  MISSING: [%s] %s", ev.service, ev.desc)
		}
	}

	t.Logf("\n=== Summary: %d/%d valid found, %d false positives ===", foundCount, len(expected), fpCount)
}
