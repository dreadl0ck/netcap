package collector_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// TestModbusHuntRulesAgainstDecodedRecords evaluates the shipped write baseline
// against real decoder output. Hand-built records cannot catch a rule that reads
// fields the decoder never populates for a given function code.
func TestModbusHuntRulesAgainstDecodedRecords(t *testing.T) {
	tcp.ResetStreamFactory()
	t.Cleanup(tcp.ResetStreamFactory)

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "plant.pcap")
	writeModbusHuntPCAP(t, pcapPath, false)
	out := filepath.Join(dir, "modbus-hunt")
	c := collector.New(collector.Config{
		Workers: 1, PacketBufferSize: 100, SnapLen: defaults.SnapLen,
		ReassembleConnections: true, OutDirPermission: 0o755,
		BaseLayer: utils.GetBaseLayer("ethernet"), DecodeOptions: utils.GetDecodeOptions("default"),
		DecoderConfig: &config.Config{
			Buffer: true, Compression: true, Proto: true, IncludeDecoders: "Modbus",
			Out: out, Source: pcapPath, IncludePayloads: true, AddContext: true,
			MemBufferSize: defaults.BufferSize, FlushEvery: defaults.FlushEvery,
			CompressionBlockSize: defaults.CompressionBlockSize, CompressionLevel: defaults.CompressionLevel,
			NumStreamWorkers: 1, StreamBufferSize: 100, Quiet: true, NoOptCheck: true,
		},
	})
	if err := c.CollectPcap(pcapPath); err != nil {
		t.Fatal(err)
	}
	r, err := netio.Open(filepath.Join(out, "Modbus.ncap.gz"), defaults.BufferSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var records []*types.Modbus
	for {
		record := new(types.Modbus)
		if err = r.Next(record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}

	// The synthetic capture writes holding register 0, so narrow the shipped
	// site placeholders to that span instead of rewriting the rule logic.
	source, err := os.ReadFile(filepath.Join("..", "rules", "examples", "modbus_hunt.yml"))
	if err != nil {
		t.Fatal(err)
	}
	adapted := filepath.Join(dir, "modbus_hunt.yml")
	replaced := strings.NewReplacer("1000", "0", "1099", "0", "1100", "1").Replace(string(source))
	if err = os.WriteFile(adapted, []byte(replaced), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := rules.LoadRulesFromFile(adapted)
	if err != nil {
		t.Fatal(err)
	}
	var rule *rules.Rule
	for _, candidate := range config.Rules {
		candidate.Enabled = true
		if candidate.Name == "Modbus Write Outside Baseline" {
			rule = candidate
		}
	}
	if rule == nil {
		t.Fatal("write baseline rule missing")
	}
	if err = rules.CompileRules(config); err != nil {
		t.Fatal(err)
	}

	var writeRequests int
	for _, record := range records {
		alert, err := rules.EvaluateRule(rule, record)
		if err != nil {
			t.Fatal(err)
		}
		// Approved master, unit and register span; every other record is either
		// an unapproved write or not a write request at all.
		want := record.MessageRole == "request" && record.FunctionCode == 6 &&
			!(record.SrcIP == "192.0.2.10" && record.UnitID == 1)
		if (alert != nil) != want {
			t.Errorf("alert=%v, want %v for %s FC%d unit %d role %q addr %d",
				alert != nil, want, record.SrcIP, record.FunctionCode, record.UnitID,
				record.MessageRole, record.Address)
		}
		if record.MessageRole == "request" && record.FunctionCode == 6 {
			writeRequests++
			// FC5/6/15/16/22 report the written span in Address/Quantity; a rule
			// gated only on WriteAddress would exempt nothing.
			if !record.HasAddress || record.HasWriteAddress {
				t.Errorf("FC6 request should use Address, not WriteAddress: %+v", record)
			}
		}
	}
	if writeRequests != 3 {
		t.Fatalf("got %d write requests, want 3", writeRequests)
	}
}
