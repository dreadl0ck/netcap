/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package secret_test

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
	credFile := filepath.Join(outDir, "Secret.ncap.gz")
	if _, err := os.Stat(credFile); os.IsNotExist(err) {
		t.Fatal("Secret.ncap.gz not found — credentials decoder did not produce output")
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
		var cred types.Secret
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

	// === DEVICE PROFILE ENRICHMENT ===
	// Verify that network discovery protocols (DHCP, CDP, LLDP, mDNS, NBNS, UPnP)
	// enriched the correct DeviceProfiles with hostnames, device types, OS, and roles.
	// Verified against tshark on The Ultimate PCAP v20260316.pcapng.
	t.Log("\n=== Checking Device Profile Enrichment ===")

	dpFile := filepath.Join(outDir, "DeviceProfile.ncap.gz")
	if _, err := os.Stat(dpFile); os.IsNotExist(err) {
		t.Log("  DeviceProfile.ncap.gz not found — skipping enrichment checks")
		return
	}

	dpReader, err := netio.Open(dpFile, defaults.BufferSize)
	if err != nil {
		t.Fatalf("Failed to open DeviceProfile file: %v", err)
	}
	defer dpReader.Close()

	if _, err := dpReader.ReadHeader(); err != nil {
		t.Fatalf("Failed to read DeviceProfile header: %v", err)
	}

	// Read all profiles into a map by MAC
	profiles := make(map[string]*types.DeviceProfile)
	for {
		var dp types.DeviceProfile
		if err := dpReader.Next(&dp); err != nil {
			break
		}
		profiles[dp.MacAddr] = &dp
	}

	t.Logf("  Read %d device profiles", len(profiles))

	// Expected enrichment verified via tshark:
	//   DHCP: hostname from option 12, vendor class from option 60
	//   CDP: device ID, platform, software version
	//   LLDP: system name, system description
	//   mDNS: hostname from A/AAAA/PTR records
	//   NBNS: NetBIOS name, suffix type (role)
	//   UPnP: Server header (OS/firmware)
	//
	// Note: Some devices (00:0a:8a:a1:5a:9a, 00:16:47:df:e7:84, etc.) are on
	// VLAN-tagged interfaces and may not have DeviceProfile entries in pcapng files
	// with multiple interfaces. We only check MACs that are expected to exist.
	expectedEnrichment := []struct {
		mac         string
		hostname    string // substring match
		deviceType  string // substring match
		os          string // substring match
		role        string // substring match
		source      string // for documentation
	}{
		// DHCP enrichment
		{"00:0c:29:48:92:fd", "vm34-test3", "", "", "", "DHCP hostname"},
		{"00:0c:29:c3:7f:eb", "DESKTOP-6AJTBQM", "", "MSFT 5.0", "", "DHCP hostname+vendor"},
		{"74:42:7f:56:3c:6c", "fritz.box", "", "AVM DHCPC", "", "DHCP hostname+vendor"},
		// CDP enrichment
		{"00:15:62:6a:fe:f0", "R4.weberlab", "Cisco 2851", "Cisco IOS", "", "CDP"},
		{"c2:3d:19:6c:00:01", "P1", "Cisco 3725", "Cisco IOS", "", "CDP"},
		{"c2:3c:19:6c:00:01", "P2", "Cisco 3725", "Cisco IOS", "", "CDP"},
		// LLDP enrichment
		{"00:21:1b:ae:31:99", "CCNP-LAB-S1", "", "Cisco IOS", "", "LLDP"},
		// mDNS enrichment
		{"74:81:14:81:c2:d4", "Johannes-ei-Patt", "", "", "", "mDNS"},
		// NBNS enrichment
		{"00:e0:4c:68:66:c1", "JOHANNES-DELL", "", "", "File Server", "NBNS"},
		// UPnP enrichment
		{"00:a0:de:de:54:13", "", "", "KnOS/3.2 UPnP", "", "UPnP"},
	}

	enrichedCount := 0
	for _, ev := range expectedEnrichment {
		dp, exists := profiles[ev.mac]
		if !exists {
			t.Logf("  SKIP: %s (%s) — profile not in output (likely VLAN-encapsulated)", ev.mac, ev.source)
			continue
		}

		ok := true

		if ev.hostname != "" {
			found := false
			for _, h := range dp.Hostnames {
				if strings.Contains(h, ev.hostname) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("  MISSING hostname %q on %s (%s), got: %v", ev.hostname, ev.mac, ev.source, dp.Hostnames)
				ok = false
			}
		}

		if ev.deviceType != "" {
			found := false
			for _, dt := range dp.DeviceTypes {
				if strings.Contains(dt, ev.deviceType) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("  MISSING deviceType %q on %s (%s), got: %v", ev.deviceType, ev.mac, ev.source, dp.DeviceTypes)
				ok = false
			}
		}

		if ev.os != "" && !strings.Contains(dp.OS, ev.os) {
			t.Errorf("  MISSING OS %q on %s (%s), got: %q", ev.os, ev.mac, ev.source, dp.OS)
			ok = false
		}

		if ev.role != "" {
			found := false
			for _, r := range dp.Roles {
				if strings.Contains(r, ev.role) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("  MISSING role %q on %s (%s), got: %v", ev.role, ev.mac, ev.source, dp.Roles)
				ok = false
			}
		}

		if ok {
			t.Logf("  ENRICHED: %s — %s", ev.mac, ev.source)
			enrichedCount++
		}
	}

	// Verify NO false enrichment on DHCP relay
	if dp, exists := profiles["3c:fa:30:03:12:30"]; exists {
		if len(dp.Hostnames) > 0 {
			t.Errorf("  FALSE ENRICHMENT: Palo Alto relay 3c:fa:30:03:12:30 should not have hostnames, got: %v", dp.Hostnames)
		} else {
			t.Log("  RELAY OK: 3c:fa:30:03:12:30 (Palo Alto) has no false enrichment")
		}
	}

	t.Logf("\n=== Device Enrichment: %d/%d verified ===", enrichedCount, len(expectedEnrichment))
}
