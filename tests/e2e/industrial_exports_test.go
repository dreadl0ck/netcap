//go:build e2e

package e2e

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

func TestIndustrialExportsCLI(t *testing.T) {
	out := t.TempDir()
	binary := filepath.Join(out, "net")
	t.Setenv("GOWORK", "off")
	t.Setenv("NC_CONFIG_ROOT", filepath.Join(out, "conf"))
	build := exec.Command("go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
	build.Dir = "../.."
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, b)
	}
	const at = 1700000000123456789
	ctx := &types.PacketContext{NetworkScope: "vlan:11", SrcMAC: "02:00:00:00:00:01"}
	end := &types.OTAssembly{FirstTimestamp: at, Pieces: 2, Status: "complete"}
	for _, tc := range []struct {
		r           types.AuditRecord
		field, want string
	}{
		{&types.PTPv2{Timestamp: at, Context: ctx, SequenceID: 1118}, "SequenceID", "1118"},
		{&types.GOOSE{Timestamp: at, Context: ctx, ControlBlock: "a;b"}, "ControlBlock", `"a;b"`},
		{&types.SampledValues{Timestamp: at, Context: ctx, SampleCounter: []uint32{5, 9}}, "SampleCounter", "[5,9]"},
		{&types.EtherCAT{Timestamp: at, Context: ctx, Commands: []string{"FPRD", "BRD"}}, "Commands", `["FPRD","BRD"]`},
		{&types.OPCUAPubSub{Timestamp: at, Context: ctx, DataSetWriterIDs: []uint32{4660}}, "DataSetWriterIDs", "[4660]"},
		{&types.IEC104{Timestamp: at, Context: ctx, Assembly: end, UFunction: "TESTFR"}, "UFunction", `"TESTFR"`},
		{&types.MMS{Timestamp: at, Context: ctx, Assembly: end, InvokeID: 4431}, "InvokeID", "4431"},
		{&types.AMS{Timestamp: at, Context: ctx, Assembly: end, ADSCommand: "ReadState"}, "ADSCommand", `"ReadState"`},
	} {
		name := strings.TrimPrefix(tc.r.NetcapType().String(), "NC_")
		t.Run(name, func(t *testing.T) {
			w := netio.NewAuditRecordWriter(&netio.WriterConfig{Out: out, Name: name, Type: tc.r.NetcapType(), Proto: true})
			if err := w.WriteHeader(tc.r.NetcapType()); err != nil {
				t.Fatal(err)
			}
			msg := tc.r.(proto.Message)
			if err := w.Write(msg); err != nil {
				t.Fatal(err)
			}
			w.Close(1)
			rows := readSemanticRecords(t, out, name)
			if len(rows) != 1 || !proto.Equal(rows[0].(proto.Message), msg) {
				t.Fatal("protobuf:", rows)
			}
			dump := func(format string) []byte {
				b, err := exec.Command(binary, "dump", "-read", filepath.Join(out, name+".ncap"), format, "-select", tc.field).Output()
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(dump("-json"), &fields); err != nil || string(fields[tc.field]) != tc.want {
				t.Fatalf("JSON: %s, %v", fields, err)
			}
			cr := csv.NewReader(bytes.NewReader(dump("-csv")))
			cr.Comma = ';'
			lines, err := cr.ReadAll()
			if err != nil || len(lines) != 2 || !slices.Equal(lines[0], []string{tc.field}) {
				t.Fatalf("CSV: %q, %v", lines, err)
			}
			expected := tc.want
			if strings.HasPrefix(expected, `"`) {
				if err := json.Unmarshal([]byte(tc.want), &expected); err != nil {
					t.Fatal(err)
				}
			}
			if lines[1][0] != expected {
				t.Fatalf("CSV %s=%q, want %q", tc.field, lines[1][0], expected)
			}
		})
	}
}
