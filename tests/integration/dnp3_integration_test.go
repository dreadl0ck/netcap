//go:build integration

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// The DNP3 corpus is cloned by `zeus dev-pcaps` (automayt/ICS-pcap) and is
// gitignored, so these skip on a clean checkout.
const dnp3Corpus = "../ICS-pcap/DNP3"

var (
	dnp3BinaryOnce sync.Once
	dnp3BinaryPath string
	dnp3BinaryErr  error
)

func dnp3Binary(tb testing.TB) string {
	tb.Helper()

	dnp3BinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "netcap-dnp3")
		if err != nil {
			dnp3BinaryErr = err

			return
		}

		dnp3BinaryPath = filepath.Join(dir, "net")

		build := exec.Command("go", "build", "-tags=nodpi", "-o", dnp3BinaryPath, "./cmd/net/")
		build.Dir = "../.."

		if out, err := build.CombinedOutput(); err != nil {
			dnp3BinaryErr = err

			tb.Logf("build output: %s", out)
		}
	})

	if dnp3BinaryErr != nil {
		tb.Fatalf("failed to build netcap: %v", dnp3BinaryErr)
	}

	return dnp3BinaryPath
}

// dnp3Records runs a capture and reads back the DNP3 audit records.
func dnp3Records(tb testing.TB, capture string) []*types.DNP3 {
	tb.Helper()
	requireFixture(tb, capture)

	// The capture runs from the repo root, so a path relative to this package
	// would resolve against the wrong directory.
	absolute, err := filepath.Abs(capture)
	if err != nil {
		tb.Fatal(err)
	}

	out := tb.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, dnp3Binary(tb), "capture",
		"-read", absolute, "-out", out,
		"-include", "DNP3", "-reassemble-connections=true", "-payload", "-quiet",
		"-http", "", // an empty address disables the web UI, which otherwise blocks

	)
	cmd.Dir = "../.."

	if output, err := cmd.CombinedOutput(); err != nil && ctx.Err() == nil {
		tb.Logf("capture finished with %v: %s", err, output)
	}

	path := filepath.Join(out, "DNP3.ncap.gz")
	if _, err := os.Stat(path); err != nil {
		tb.Fatalf("decoder produced no output for %s", capture)
	}

	reader, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		tb.Fatal(err)
	}
	defer reader.Close()

	if _, err := reader.ReadHeader(); err != nil {
		tb.Fatal(err)
	}

	var records []*types.DNP3

	for {
		record := &types.DNP3{}
		if err := reader.Next(record); err != nil {
			break
		}

		records = append(records, record)
	}

	return records
}

// Ground truth is the capture's committed Zeek dnp3.log. Zeek reports the
// second IIN octet where netcap reports the full 16 bits, so the expected
// values below are shifted accordingly.
func TestDNP3MatchesZeekReference(t *testing.T) {
	records := dnp3Records(t, filepath.Join(dnp3Corpus, "DNP3-TestDataPart2", "DNP3-TestDataPart2.pcap"))

	want := []struct {
		timestamp int64
		iin       int32
	}{
		{1178205958184068000, 0},
		{1178205982425227000, 0x0400},
		{1178205984486492000, 0x0400},
		{1178205985311235000, 0x0400},
		{1178205986029976000, 0x0400},
		{1178205986556099000, 0x0400},
		{1178206042953163000, 0x0600},
		{1178206044500956000, 0x0600},
		{1178206045032815000, 0x0600},
		{1178206045557097000, 0x0600},
		{1178206046086403000, 0x0600},
	}

	var got []*types.DNP3

	for _, r := range records {
		if r.ParseStatus == "valid" && r.FunctionCodeName == "RESPONSE" {
			got = append(got, r)
		}
	}

	if len(got) != len(want) {
		t.Fatalf("got %d responses, Zeek reports %d", len(got), len(want))
	}

	for i, w := range want {
		if got[i].Timestamp != w.timestamp {
			t.Errorf("response %d timestamp = %d, Zeek reports %d", i, got[i].Timestamp, w.timestamp)
		}
		if got[i].InternalIndications != w.iin {
			t.Errorf("response %d IIN = %#04x, want %#04x", i, got[i].InternalIndications, w.iin)
		}
		// Responses travel outstation to master, so their endpoints are
		// reversed. Recording them with the master's address would make a
		// reply indistinguishable from a command.
		if got[i].SrcIP != "192.168.66.34" || got[i].SrcPort != 20000 {
			t.Errorf("response %d attributed to %s:%d, want the outstation", i, got[i].SrcIP, got[i].SrcPort)
		}
	}
}

// Wireshark's dissector reports these controls as index 34463, Latch On,
// count 1, on and off time 100, behind a 2-octet index prefix and a 2-octet
// count.
func TestDNP3ControlBlocksMatchDissector(t *testing.T) {
	records := dnp3Records(t, filepath.Join(dnp3Corpus, "DNP3-TestDataPart2", "DNP3-TestDataPart2.pcap"))

	var blocks int

	for _, r := range records {
		if r.ParseStatus != "valid" || r.FunctionCodeName != "SELECT" {
			continue
		}

		if len(r.Objects) != 1 {
			t.Fatalf("got %d objects on a SELECT, want exactly 1", len(r.Objects))
		}

		obj := r.Objects[0]
		if obj.ObjectGroup != 12 || obj.Variation != 1 {
			t.Errorf("object = group %d variation %d, want 12/1", obj.ObjectGroup, obj.Variation)
		}
		if obj.PrefixCode != 2 || obj.RangeSpecifier != 8 {
			t.Errorf("qualifier decoded as prefix %d range %d, want 2/8", obj.PrefixCode, obj.RangeSpecifier)
		}

		for _, c := range obj.ControlBlocks {
			blocks++

			if c.Index != 34463 || c.ControlCodeName != "LATCH_ON" || c.Count != 1 {
				t.Errorf("control block = index %d %q count %d", c.Index, c.ControlCodeName, c.Count)
			}
			if c.OnTime != 100 || c.OffTime != 100 {
				t.Errorf("control block timing = on %d off %d, want 100/100", c.OnTime, c.OffTime)
			}
		}
	}

	if blocks != 5 {
		t.Errorf("decoded %d control blocks, want 5", blocks)
	}
}

func TestDNP3SelectOperatePairs(t *testing.T) {
	records := dnp3Records(t, filepath.Join(dnp3Corpus, "DNP3-SelectOperate", "DNP3-SelectOperate.pcap"))

	var sel, op *types.DNP3

	for _, r := range records {
		switch r.FunctionCodeName {
		case "SELECT":
			sel = r
		case "OPERATE":
			op = r
		}
	}

	if sel == nil || op == nil {
		t.Fatal("capture did not yield a Select and an Operate")
	}
	if sel.SBOStatus != "matched" || op.SBOStatus != "matched" {
		t.Errorf("SBO status: select=%q operate=%q", sel.SBOStatus, op.SBOStatus)
	}
	if op.SelectTimestamp != sel.Timestamp {
		t.Errorf("operate references a select at %d, the select is at %d", op.SelectTimestamp, sel.Timestamp)
	}
	// One timestamp for a whole conversation makes every window question
	// unanswerable, so the two must differ.
	if op.Timestamp == sel.Timestamp {
		t.Error("select and operate share a timestamp")
	}
	// Zeek reports the Operate at 1227729908.575758.
	if op.Timestamp != 1227729908575758000 {
		t.Errorf("operate timestamp = %d, Zeek reports 1227729908575758000", op.Timestamp)
	}
}

// A sweep of every qualifier code. Each frame's link header authenticates, so
// the decoder has to report what it cannot size rather than assembling objects
// out of the previous object's values.
func TestDNP3QualifierFuzzCorpus(t *testing.T) {
	records := dnp3Records(t, filepath.Join(dnp3Corpus, "DNP3-Malformed", "DNP3-Malformed.pcap"))

	var operates, truncated, malformed, fabricated int

	for _, r := range records {
		switch r.ParseStatus {
		case "malformed":
			malformed++

			if !r.HeaderCRCValid {
				t.Error("a malformed record was emitted for a frame whose header CRC failed")
			}
		case "valid":
			if r.FunctionCodeName != "OPERATE" {
				continue
			}

			operates++

			if r.ObjectsTruncated {
				truncated++
			}

			for _, o := range r.Objects {
				// Only group 12 was sent; any other group came from misreading
				// a control block's payload as an object header.
				if o.ObjectGroup != 12 {
					fabricated++
				}
			}
		}
	}

	if operates < 190 {
		t.Errorf("decoded %d OPERATE frames, want ~196", operates)
	}
	if fabricated != 0 {
		t.Errorf("%d objects were assembled from object values", fabricated)
	}
	if truncated == 0 {
		t.Error("no frame reported truncated objects, but this corpus sweeps every qualifier")
	}
	if malformed != 1 {
		t.Errorf("got %d malformed records, want the one length-below-minimum frame", malformed)
	}
}

// A capture that begins with no SYN must still be claimed by the port-based
// decoder. Reassembly prepends an empty initial-loss marker, and detection run
// on that marker rejects the real protocol.
func TestDNP3MidstreamCaptureIsClaimed(t *testing.T) {
	records := dnp3Records(t, filepath.Join(dnp3Corpus, "DNP3-TestDataPart2", "DNP3-TestDataPart2.pcap"))

	var decoded, lost int

	for _, r := range records {
		switch r.ParseStatus {
		case "valid":
			decoded++
		case "lost":
			lost++

			if r.LostBytes != -1 {
				t.Errorf("initial loss reported as %d bytes, want -1 for an unknown amount", r.LostBytes)
			}
		}
	}

	if decoded == 0 {
		t.Fatal("midstream capture produced no decoded records")
	}
	// One marker per direction, so the capture cannot be read as contiguous.
	if lost != 2 {
		t.Errorf("got %d loss markers, want one per direction", lost)
	}
}
