//go:build e2e

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package tests_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
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
	pcap, err := os.Open(pcapFile)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, pcap)
	_ = pcap.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", hash.Sum(nil)); got != "da101f5fcdda39399a440a9b994ce835d54fe73b4a2325d26de47c4d168a252c" {
		t.Fatalf("Ultimate PCAP fixture changed: %s", got)
	}
	wantKerberos := kerberosKDCOracle(t, pcapFile)
	wantIPP := ippHTTPOracle(t, pcapFile)

	// Build the netcap binary
	binaryPath := filepath.Join(t.TempDir(), "netcap-test")
	buildCmd := exec.Command("go", "build", "-tags=nodpi", "-o", binaryPath, "./cmd/net/")
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
		t.Fatalf("Capture timed out: %s", out)
	} else if err != nil {
		t.Fatalf("Capture failed: %v\nOutput: %s", err, string(out))
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
		{"LLMNR", "LLMNR.ncap.gz", types.Type_NC_LLMNR, 18},              // tshark: 18, exact match
		{"STUN", "STUN.ncap.gz", types.Type_NC_STUN, 22},                 // tshark: 22, exact match
		{"PIM", "PIM.ncap.gz", types.Type_NC_PIM, 300},                   // tshark: 384, netcap: ~333
		{"NetFlowV9", "NetFlowV9.ncap.gz", types.Type_NC_NetFlowV9, 190}, // tshark(cflow): 196, exact match
		{"CLDAP", "CLDAP.ncap.gz", types.Type_NC_CLDAP, 100},             // tshark: 106, exact match
		{"ISIS", "ISIS.ncap.gz", types.Type_NC_ISIS, 670},                // tshark: 678, exact match
		{"OCSP", "OCSP.ncap.gz", types.Type_NC_OCSP, 10},                 // tshark: 29, netcap: ~16 (many in TLS)
		{"RARP", "RARP.ncap.gz", types.Type_NC_RARP, 1},                  // tshark(rarp): 0, netcap: 4 (detected via EtherType)

		// Stream decoders — counts differ from tshark frame counts
		// The other 134 tshark Kerberos packets are embedded SMB/RPC tokens.
		{"Kerberos", "Kerberos.ncap.gz", types.Type_NC_Kerberos, 134},
		{"TACACS", "TACACS.ncap.gz", types.Type_NC_TACACS, 18},  // tshark(tacplus): 18, exact match
		{"DCERPC", "DCERPC.ncap.gz", types.Type_NC_DCERPC, 350}, // tshark: 420, netcap: ~368
		{"IPP", "IPP.ncap.gz", types.Type_NC_IPP, 38},           // 19 requests + 19 responses, verified below
		{"Zabbix", "Zabbix.ncap.gz", types.Type_NC_Zabbix, 40},  // tshark: 150, netcap: ~51 (session-based)
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
			gotKerberos := make(map[string]int)
			gotIPP := make(map[string]int)
			record := netio.InitRecord(dt.typ)
			if record == nil {
				t.Fatalf("InitRecord returned nil for type %s", dt.typ)
			}

			for {
				if err := reader.Next(record); err != nil {
					if err != io.EOF {
						t.Fatalf("decode %s: %v", dt.name, err)
					}
					break
				}
				count++
				if rec, ok := record.(*types.IPP); ok {
					key := fmt.Sprintf("%d|%d|%s|%s|%d|%d|%d", rec.RequestID, rec.OperationOrStatus, rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort, rec.VersionMajor<<8|rec.VersionMinor)
					gotIPP[key]++
					if rec.CommunityID == "" || rec.Timestamp == 0 || rec.SrcPort == 631 && rec.OperationName != "successful-ok" {
						t.Fatalf("IPP observation missing attribution or response semantics: %v", rec)
					}
				}
				if rec, ok := record.(*types.Kerberos); ok {
					key := fmt.Sprintf("%d|%s|%s|%d|%d", rec.MessageTypeCode, rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort)
					gotKerberos[key]++
					if rec.CommunityID == "" || rec.Timestamp == 0 {
						t.Fatal("Kerberos observation missing correlation or timestamp")
					}
				}
			}
			if dt.typ == types.Type_NC_Kerberos && !reflect.DeepEqual(gotKerberos, wantKerberos) {
				t.Errorf("KDC message/direction multiset differs from tshark:\ngot %v\nwant %v", gotKerberos, wantKerberos)
			}
			if dt.typ == types.Type_NC_IPP && !reflect.DeepEqual(gotIPP, wantIPP) {
				t.Errorf("IPP message/direction multiset differs from tshark:\ngot %v\nwant %v", gotIPP, wantIPP)
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

func ippHTTPOracle(t *testing.T, pcap string) map[string]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tshark", "-r", pcap, "-Y", "ipp", "-T", "fields", "-E", "occurrence=f",
		"-e", "ipp.request_id", "-e", "ipp.operation_id", "-e", "ipp.status_code", "-e", "ipv6.src", "-e", "ipv6.dst",
		"-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "ipp.version").Output()
	if err != nil {
		t.Fatalf("IPP oracle failed: %v", err)
	}
	result := make(map[string]int)
	requests, responses := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 8 {
			t.Fatalf("invalid IPP oracle row: %q", line)
		}
		code := fields[1]
		if code == "" {
			code = fields[2]
			responses++
		} else {
			requests++
		}
		n, err := strconv.ParseUint(code, 0, 16)
		if err != nil {
			t.Fatalf("invalid IPP operation/status: %q", line)
		}
		result[fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s", fields[0], n, fields[3], fields[4], fields[5], fields[6], fields[7])]++
	}
	if requests != 19 || responses != 19 {
		t.Fatalf("IPP corpus changed: %d requests, %d responses", requests, responses)
	}
	return result
}

func kerberosKDCOracle(t *testing.T, pcap string) map[string]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	version, err := exec.CommandContext(ctx, "tshark", "--version").Output()
	if err != nil {
		t.Fatalf("required tshark oracle: %v", err)
	}
	t.Log(strings.SplitN(string(version), "\n", 2)[0])
	out, err := exec.CommandContext(ctx, "tshark", "-r", pcap, "-Y", "kerberos && tcp.port == 88", "-T", "fields", "-E", "occurrence=f",
		"-e", "kerberos.msg_type", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "tcp.dstport").Output()
	if err != nil {
		t.Fatalf("KDC oracle failed: %v", err)
	}
	result := make(map[string]int)
	histogram := make(map[int]int)
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 7 {
			t.Fatalf("invalid KDC oracle row: %q", line)
		}
		code, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatal(err)
		}
		histogram[code]++
		result[strings.Join([]string{fields[0], fields[1] + fields[2], fields[3] + fields[4], fields[5], fields[6]}, "|")]++
	}
	if !reflect.DeepEqual(histogram, map[int]int{10: 35, 11: 16, 12: 32, 13: 32, 30: 19}) {
		t.Fatalf("pinned standalone KDC histogram changed: %v", histogram)
	}
	return result
}
