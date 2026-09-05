package types

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
)

func TestModbusCSVAndEncode(t *testing.T) {
	oldSelection, oldUTC := selection, UTC
	selection, UTC = nil, false
	encoder.SetConfig(&encoder.Config{MinMax: true})
	t.Cleanup(func() {
		selection, UTC = oldSelection, oldUTC
		encoder.SetConfig(nil)
	})

	a := &Modbus{
		Timestamp: 1700000000123456789, TransactionID: 17, ProtocolID: 2,
		Length: 6, UnitID: 4, Payload: []byte{0, 0xab, 0xff},
		Exception: true, FunctionCode: 3,
	}
	ctx := &PacketContext{
		SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: 12345, DstPort: 502,
		CommunityID: "1:modbus-test",
	}
	a.SetPacketContext(ctx)
	if a.Src() != ctx.SrcIP || a.Dst() != ctx.DstIP || a.SrcPort != ctx.SrcPort ||
		a.DstPort != ctx.DstPort || a.CommunityID != ctx.CommunityID {
		t.Fatalf("packet context not preserved: %+v", a)
	}
	wantHeader := []string{
		"Timestamp", "TransactionID", "ProtocolID", "Length", "UnitID", "Payload",
		"Exception", "FunctionCode", "SrcIP", "DstIP", "SrcPort", "DstPort", "CommunityID",
	}
	wantCSV := []string{
		formatTimestamp(a.Timestamp), "17", "2", "6", "4", "00abff", "true", "3",
		ctx.SrcIP, ctx.DstIP, "12345", "502", ctx.CommunityID,
	}
	if got := a.CSVHeader(); !reflect.DeepEqual(got, wantHeader) {
		t.Fatalf("header = %v, want %v", got, wantHeader)
	}
	if got := a.CSVRecord(); !reflect.DeepEqual(got, wantCSV) {
		t.Fatalf("CSV = %v, want %v", got, wantCSV)
	}
	encoded := a.Encode()
	if len(encoded) != len(wantHeader) {
		t.Fatalf("encoded columns = %d, want %d", len(encoded), len(wantHeader))
	}
	for i, value := range encoded {
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			t.Errorf("encoded %s is not numeric: %q", wantHeader[i], value)
		}
	}
	if encoded[5] != modbusEncoder.String(fieldPayload, "00abff") ||
		encoded[6] != modbusEncoder.Bool(true) ||
		encoded[12] != modbusEncoder.String(fieldCommunityID, ctx.CommunityID) {
		t.Fatalf("misaligned encoded payload, exception, or CommunityID: %v", encoded)
	}
	for _, indices := range [][]int{{12, 5, 6, 10, 0}, {7, 11, 12, 5, 5}, {12}} {
		selection = nil
		names := make([]string, len(indices))
		for i, index := range indices {
			names[i] = wantHeader[index]
		}
		Select(a, strings.Join(names, ","))
		header, csv, enc := a.CSVHeader(), a.CSVRecord(), a.Encode()
		if len(header) != len(indices) || len(csv) != len(indices) || len(enc) != len(indices) {
			t.Fatalf("projection lengths: header=%d CSV=%d encoded=%d", len(header), len(csv), len(enc))
		}
		for i, index := range indices {
			if header[i] != wantHeader[index] || csv[i] != wantCSV[index] || enc[i] != encoded[index] {
				t.Errorf("projection %v column %d: got %q/%q/%q", indices, i, header[i], csv[i], enc[i])
			}
		}
	}
}

func TestModbusJSONDoesNotMutate(t *testing.T) {
	a := &Modbus{
		Timestamp: 1700000000123456789, Payload: []byte{0, 0xab, 0xff},
		TransactionID: 17, Exception: true, CommunityID: "1:modbus-json",
	}
	before := proto.Clone(a).(*Modbus)
	csvBefore := a.CSVRecord()
	wireBefore, err := proto.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for i := 0; i < 3; i++ {
		got, err := a.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("JSON changed on call %d: %s", i+1, got)
		}
		var decoded struct {
			Timestamp   string
			Payload     []byte
			CommunityID string
		}
		if err := json.Unmarshal([]byte(got), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Timestamp != strconv.FormatInt(before.Timestamp/int64(time.Millisecond), 10) ||
			!reflect.DeepEqual(decoded.Payload, before.Payload) || decoded.CommunityID != before.CommunityID {
			t.Fatalf("unexpected JSON values: %s", got)
		}
		if !proto.Equal(a, before) || a.Time() != before.Timestamp || !reflect.DeepEqual(a.CSVRecord(), csvBefore) {
			t.Fatal("JSON mutated the record, Time(), or CSV output")
		}
		wireAfter, err := proto.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(wireAfter, wireBefore) {
			t.Fatal("JSON changed protobuf output")
		}
	}
}

func TestModbusMetricsIgnoreProjection(t *testing.T) {
	oldSelection, oldMetric := selection, modbusTCPMetric
	selection = nil
	modbusTCPMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_modbus", Help: "Modbus test records",
	}, fieldsModbus[1:])
	t.Cleanup(func() { selection, modbusTCPMetric = oldSelection, oldMetric })
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(modbusTCPMetric)
	a := &Modbus{TransactionID: 7, Payload: []byte{0xab}, Exception: true, CommunityID: "1:metrics"}
	header, values := a.CSVHeader(), a.CSVRecord()
	for _, projection := range [][]int{nil, {12, 5, 0}, {0}, {12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}} {
		selection = projection
		a.Inc()
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 1 || len(families[0].Metric) != 1 {
		t.Fatalf("expected one metric series: %v", families)
	}
	metric := families[0].Metric[0]
	if got := metric.GetCounter().GetValue(); got != 4 {
		t.Errorf("counter = %v, want 4", got)
	}
	labels := make(map[string]string)
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	if len(labels) != len(header)-1 {
		t.Fatalf("label count = %d, want %d", len(labels), len(header)-1)
	}
	for i := 1; i < len(header); i++ {
		if got, ok := labels[header[i]]; !ok || got != values[i] {
			t.Errorf("label %s = %q (present=%v), want %q", header[i], got, ok, values[i])
		}
	}
}
