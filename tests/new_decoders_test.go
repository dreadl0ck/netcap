/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package tests_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// TestNewDecoders_UltimatePCAP builds and runs netcap on the Ultimate PCAP,
// then verifies that each new protocol decoder produces the expected number
// of audit records. Expected counts are cross-referenced with tshark.
//
// tshark counts (The Ultimate PCAP v20260316.pcapng):
//
//	llmnr:18  stun:22  kerberos:268  tacplus:18  pim:384  ocsp:29
//	ipp:38  zabbix:150  cldap:106  isis:678  dcerpc:420  cflow:196  rarp:0
//
// netcap counts may differ from tshark due to:
//   - Stream decoders count reassembled sessions, not individual frames
//   - Some protocols are encrypted (OCSP over TLS) and invisible to netcap
//   - Port-based filtering may exclude some traffic
func TestNewDecoders_UltimatePCAP(t *testing.T) {
	repoRoot, _ := filepath.Abs("..")
	pcapFile := filepath.Join(repoRoot, "tests", "The Ultimate PCAP v20260316.pcapng")
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("The Ultimate PCAP v20260316.pcapng not found in tests/")
	}

	// Build the netcap binary
	binaryPath := filepath.Join(t.TempDir(), "netcap-test")
	buildCmd := exec.Command("go", "build", "-tags=nodpi", "-o", binaryPath, "./cmd/")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build netcap binary: %v\n%s", err, out)
	}

	// Run netcap capture
	outDir := filepath.Join(t.TempDir(), "output")
	os.MkdirAll(outDir, 0o700)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
		t.Log("Capture timed out during cleanup (records already written)")
	} else if err != nil {
		t.Logf("Capture finished with: %v\nOutput: %s", err, string(out))
	}
	t.Log("Capture complete.")

	// All 13 new protocol decoders with expected minimum record counts.
	// minCount is set conservatively below actual netcap output to allow
	// for minor variations across runs.
	decoderTests := []struct {
		name     string
		ncapFile string
		typ      types.Type
		minCount int // minimum expected records
	}{
		// Packet decoders — counts match or are close to tshark
		{"LLMNR", "LLMNR.ncap.gz", types.Type_NC_LLMNR, 18},       // tshark: 18, exact match
		{"STUN", "STUN.ncap.gz", types.Type_NC_STUN, 22},           // tshark: 22, exact match
		{"PIM", "PIM.ncap.gz", types.Type_NC_PIM, 300},             // tshark: 384, netcap: ~333
		{"NetFlowV9", "NetFlowV9.ncap.gz", types.Type_NC_NetFlowV9, 190}, // tshark(cflow): 196, exact match
		{"CLDAP", "CLDAP.ncap.gz", types.Type_NC_CLDAP, 100},      // tshark: 106, exact match
		{"ISIS", "ISIS.ncap.gz", types.Type_NC_ISIS, 670},          // tshark: 678, exact match
		{"OCSP", "OCSP.ncap.gz", types.Type_NC_OCSP, 10},          // tshark: 29, netcap: ~16 (many in TLS)
		{"RARP", "RARP.ncap.gz", types.Type_NC_RARP, 1},           // tshark(rarp): 0, netcap: 4 (detected via EtherType)

		// Stream decoders — counts differ from tshark frame counts
		// Kerberos current baseline after collector pool resets landed: ~208–210.
		// Older value 243-246 reflected runs where UDP stream pool state leaked
		// between captures in the same process. Threshold lowered accordingly.
		{"Kerberos", "Kerberos.ncap.gz", types.Type_NC_Kerberos, 200},  // tshark: 268, netcap: ~208-210
		{"TACACS", "TACACS.ncap.gz", types.Type_NC_TACACS, 18},         // tshark(tacplus): 18, exact match
		{"DCERPC", "DCERPC.ncap.gz", types.Type_NC_DCERPC, 350},       // tshark: 420, netcap: ~368
		{"IPP", "IPP.ncap.gz", types.Type_NC_IPP, 30},                 // tshark: 38, netcap: ~39
		{"Zabbix", "Zabbix.ncap.gz", types.Type_NC_Zabbix, 40},        // tshark: 150, netcap: ~51 (session-based)
	}

	for _, dt := range decoderTests {
		t.Run(dt.name, func(t *testing.T) {
			ncapPath := filepath.Join(outDir, dt.ncapFile)
			if _, err := os.Stat(ncapPath); os.IsNotExist(err) {
				t.Fatalf("%s not found — decoder did not produce output", dt.ncapFile)
				return
			}

			reader, err := netio.Open(ncapPath, defaults.BufferSize)
			if err != nil {
				t.Fatalf("Failed to open %s: %v", dt.ncapFile, err)
			}
			defer reader.Close()

			if _, err := reader.ReadHeader(); err != nil {
				t.Fatalf("Failed to read header: %v", err)
			}

			count := 0
			record := netio.InitRecord(dt.typ)
			if record == nil {
				t.Fatalf("InitRecord returned nil for type %s", dt.typ)
			}

			for {
				if err := reader.Next(record); err != nil {
					break
				}
				count++
			}

			t.Logf("%s: %d records (minimum expected: %d)", dt.name, count, dt.minCount)
			if count < dt.minCount {
				t.Errorf("%s: expected at least %d records, got %d", dt.name, dt.minCount, count)
			}
		})
	}

	// Verify existing decoders still produce output
	for _, name := range []string{"DNS", "TCP", "Ethernet", "IPv4"} {
		t.Run("Existing_"+name, func(t *testing.T) {
			ncapPath := filepath.Join(outDir, name+".ncap.gz")
			if _, err := os.Stat(ncapPath); os.IsNotExist(err) {
				t.Errorf("Existing decoder %s did not produce output", name)
			}
		})
	}
}
