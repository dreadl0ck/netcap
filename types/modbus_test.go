package types

import (
	"encoding/json"
	"hash/crc32"
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
	oldSelection, oldUTC, oldEncoder := selection, UTC, modbusEncoder
	selection, UTC = nil, false
	modbusEncoder = encoder.NewValueEncoder()
	encoder.SetConfig(&encoder.Config{MinMax: true})
	t.Cleanup(func() {
		selection, UTC = oldSelection, oldUTC
		modbusEncoder = oldEncoder
		encoder.SetConfig(nil)
	})

	a := &Modbus{
		Timestamp: 1700000000123456789, TransactionID: 17, ProtocolID: 2,
		Length: 6, UnitID: 4, Payload: []byte{0, 0xab, 0xff},
		Exception: true, FunctionCode: 3,
		Transport: "tcp", MessageRole: "response", ParseStatus: "partial", ParseError: "bad,\"value\"\n", Bank: "holding",
		HasAddress: true, Address: 65535, Quantity: 2, Values: []uint32{0, 65535},
		HasReadAddress: true, ReadAddress: 12, ReadQuantity: 3,
		HasWriteAddress: true, WriteAddress: 14, WriteQuantity: 4, WriteValues: []uint32{1, 2},
		ExceptionCode: 2, HasDiagnostic: true, DiagnosticSubfunction: 10, DiagnosticData: []byte{0, 255},
		MEIType: 14, ReadDeviceIDCode: 4,
		DeviceIDObjects: []*ModbusDeviceIDObject{{ID: 1, Value: []byte{0, 255}}, {}},
		FileRecords:     []*ModbusFileRecord{{ReferenceType: 6, FileNumber: 7, RecordNumber: 8, RecordLength: 2, Values: []uint32{0, 65535}}},
		AndMask:         65535, OrMask: 32768, CorrelationStatus: "matched", RequestTimestamp: 1700000000123000000, ResponseLatency: 456789,
		DeviceIDObjectID: 5, DeviceIDConformityLevel: 131, DeviceIDMoreFollows: true, DeviceIDNextObjectID: 6,
		HasMBAP: true, HasChecksum: true, ChecksumValid: true, Broadcast: true, LostBytes: 400,
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
		"Transport", "MessageRole", "ParseStatus", "ParseError", "Bank", "HasAddress", "Address", "Quantity", "Values",
		"HasReadAddress", "ReadAddress", "ReadQuantity", "HasWriteAddress", "WriteAddress", "WriteQuantity", "WriteValues",
		"ExceptionCode", "HasDiagnostic", "DiagnosticSubfunction", "DiagnosticData", "MEIType", "ReadDeviceIDCode",
		"DeviceIDObjects", "FileRecords", "AndMask", "OrMask", "CorrelationStatus", "RequestTimestamp", "ResponseLatency",
		"DeviceIDObjectID", "DeviceIDConformityLevel", "DeviceIDMoreFollows", "DeviceIDNextObjectID",
		"HasMBAP", "HasChecksum", "ChecksumValid", "Broadcast", "LostBytes",
	}
	wantCSV := []string{
		formatTimestamp(a.Timestamp), "17", "2", "6", "4", "00abff", "true", "3",
		ctx.SrcIP, ctx.DstIP, "12345", "502", ctx.CommunityID,
		"tcp", "response", "partial", "bad,\"value\"\n", "holding", "true", "65535", "2", "[0,65535]",
		"true", "12", "3", "true", "14", "4", "[1,2]", "2", "true", "10", "00ff", "14", "4",
		`[{"ID":1,"Value":"AP8="},{}]`,
		`[{"ReferenceType":6,"FileNumber":7,"RecordNumber":8,"RecordLength":2,"Values":[0,65535]}]`,
		"65535", "32768", "matched", formatTimestamp(a.RequestTimestamp), "456789", "5", "131", "true", "6",
		"true", "true", "true", "true", "400",
	}
	if got := a.CSVHeader(); !reflect.DeepEqual(got, wantHeader) {
		t.Fatalf("header = %v, want %v", got, wantHeader)
	}
	if got := a.CSVRecord(); !reflect.DeepEqual(got, wantCSV) {
		t.Fatalf("CSV = %v, want %v", got, wantCSV)
	}
	// Fail explicitly when the generated schema gains fields needing output support.
	typ := reflect.TypeOf(*a)
	for i := range typ.NumField() {
		field := typ.Field(i)
		if tag := field.Tag.Get("protobuf"); tag != "" {
			number, err := strconv.Atoi(strings.Split(tag, ",")[1])
			if err != nil || number > len(wantHeader) || wantHeader[number-1] != field.Name {
				t.Fatalf("protobuf field missing/misaligned in output: %s (%s)", field.Name, tag)
			}
		}
	}
	wire, err := proto.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Modbus
	if err := proto.Unmarshal(wire, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(a, &roundtrip) || !reflect.DeepEqual(roundtrip.CSVRecord(), wantCSV) {
		t.Fatal("expanded protobuf roundtrip changed evidence")
	}
	before := proto.Clone(a).(*Modbus)
	for range 3 {
		text, err := a.JSON()
		if err != nil {
			t.Fatal(err)
		}
		expected := proto.Clone(before).(*Modbus)
		expected.Timestamp /= int64(time.Millisecond)
		want, err := jsonMarshaler.MarshalToString(expected)
		if err != nil {
			t.Fatal(err)
		}
		if text != want || !proto.Equal(a, before) {
			t.Fatal("expanded JSON changed evidence or record")
		}
	}
	reference := encoder.NewValueEncoder()
	encoder.SetConfig(&encoder.Config{MinMax: true})
	wantEncoded := make([]string, len(wantHeader))
	for i, field := range wantHeader {
		for _, e := range []*encoder.ValueEncoder{reference, modbusEncoder} {
			e.Float64(field, 0)
			e.Float64(field, 65535)
		}
		var number float64
		switch field {
		case "SrcIP", "DstIP":
			wantEncoded[i] = reference.String(field, wantCSV[i])
			continue
		case "Exception", "HasAddress", "HasReadAddress", "HasWriteAddress", "HasDiagnostic", "DeviceIDMoreFollows", "HasMBAP", "HasChecksum", "ChecksumValid", "Broadcast":
			wantEncoded[i] = reference.Bool(wantCSV[i] == "true")
			continue
		case "Timestamp":
			number = float64(a.Timestamp)
		case "RequestTimestamp":
			number = float64(a.RequestTimestamp)
		case "Payload":
			number = float64(crc32.ChecksumIEEE(a.Payload) & 0xffff)
		case "DiagnosticData":
			number = float64(crc32.ChecksumIEEE(a.DiagnosticData) & 0xffff)
		case "CommunityID", "Transport", "MessageRole", "ParseStatus", "ParseError", "Bank", "CorrelationStatus", "Values", "WriteValues", "DeviceIDObjects", "FileRecords":
			number = float64(crc32.ChecksumIEEE([]byte(wantCSV[i])) & 0xffff)
		default:
			var err error
			number, err = strconv.ParseFloat(wantCSV[i], 64)
			if err != nil {
				t.Fatal(err)
			}
		}
		wantEncoded[i] = reference.Float64(field, number)
	}
	encoded := a.Encode()
	if !reflect.DeepEqual(encoded, wantEncoded) {
		t.Fatalf("Encode = %v, want %v", encoded, wantEncoded)
	}
	if len(encoded) != len(wantHeader) {
		t.Fatalf("encoded columns = %d, want %d", len(encoded), len(wantHeader))
	}
	for i, value := range encoded {
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			t.Errorf("encoded %s is not numeric: %q", wantHeader[i], value)
		}
	}
	if encoded[5] != modbusEncoder.Uint32(fieldPayload, crc32.ChecksumIEEE(a.Payload)&0xffff) ||
		encoded[6] != modbusEncoder.Bool(true) ||
		encoded[12] != modbusEncoder.Uint32(fieldCommunityID, crc32.ChecksumIEEE([]byte(ctx.CommunityID))&0xffff) {
		t.Fatalf("misaligned encoded payload, exception, or CommunityID: %v", encoded)
	}
	indicesAll := make([]int, len(wantHeader))
	for i := range indicesAll {
		indicesAll[i] = len(wantHeader) - 1 - i
	}
	for _, indices := range [][]int{indicesAll, {12, 5, 6, 10, 0}, {7, 11, 12, 5, 5}, {12}, {36, 35, 32, 21, 28, 16, 35}} {
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
	// A loss marker reports an unknown gap as -1 and keeps the column count.
	selection = nil
	marker := &Modbus{ParseStatus: "lost", Transport: "tcp", LostBytes: -1}
	header, csv, enc := marker.CSVHeader(), marker.CSVRecord(), marker.Encode()
	if len(header) != len(wantHeader) || len(csv) != len(wantHeader) || len(enc) != len(wantHeader) {
		t.Fatalf("loss marker columns: %d/%d/%d", len(header), len(csv), len(enc))
	}
	if csv[len(csv)-1] != "-1" || header[len(header)-1] != "LostBytes" {
		t.Fatalf("loss marker LostBytes column: %q/%q", header[len(header)-1], csv[len(csv)-1])
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
	}, []string{fieldFunctionCode, fieldException})
	t.Cleanup(func() { selection, modbusTCPMetric = oldSelection, oldMetric })
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(modbusTCPMetric)
	a := &Modbus{FunctionCode: 3, Exception: true}
	for _, projection := range [][]int{nil, {12, 5, 0}, {0}, {12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}} {
		selection = projection
		for i := range 1000 {
			a.Timestamp++
			a.TransactionID++
			a.ProtocolID++
			a.Length++
			a.UnitID++
			a.Payload = []byte("secret-payload-" + strconv.Itoa(i))
			a.SrcIP = "source-" + strconv.Itoa(i)
			a.DstIP = "destination-" + strconv.Itoa(i)
			a.SrcPort++
			a.DstPort++
			a.CommunityID = "secret-flow-" + strconv.Itoa(i)
			a.Inc()
		}
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 1 || len(families[0].Metric) != 1 {
		t.Fatalf("expected one metric series: %v", families)
	}
	metric := families[0].Metric[0]
	if got := metric.GetCounter().GetValue(); got != 4000 {
		t.Errorf("counter = %v, want 4000", got)
	}
	labels := make(map[string]string)
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	if want := (map[string]string{fieldFunctionCode: "3", fieldException: "true"}); !reflect.DeepEqual(labels, want) {
		t.Fatalf("labels = %v, want %v (no payload or flow disclosure)", labels, want)
	}
	for _, code := range []int32{-1, 256, 2147483647} {
		a.FunctionCode = code
		a.Inc()
	}
	families, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families[0].Metric) != 2 {
		t.Fatalf("invalid function codes must share one additional series: %v", families)
	}
	for _, metric := range families[0].Metric {
		for _, label := range metric.Label {
			if label.GetName() == fieldFunctionCode && label.GetValue() != "3" {
				if label.GetValue() != "unknown" || metric.GetCounter().GetValue() != 3 {
					t.Fatalf("unexpected invalid function code series: %v", metric)
				}
			}
		}
	}
	// Loss markers carry no function code and must not look like FC0.
	marker := &Modbus{ParseStatus: "lost", LostBytes: -1}
	marker.Inc()
	families, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, metric := range families[0].Metric {
		for _, label := range metric.Label {
			if label.GetName() == fieldFunctionCode && label.GetValue() == "lost" {
				found = true
			}
			if label.GetName() == fieldFunctionCode && label.GetValue() == "0" {
				t.Fatal("loss marker counted as function code 0")
			}
		}
	}
	if !found {
		t.Fatalf("loss marker series missing: %v", families[0].Metric)
	}
}

func TestModbusEncodeBoundedState(t *testing.T) {
	oldSelection, oldEncoder := selection, modbusEncoder
	t.Cleanup(func() {
		selection, modbusEncoder = oldSelection, oldEncoder
		encoder.SetConfig(nil)
	})
	for _, projected := range []bool{false, true} {
		modbusEncoder = encoder.NewValueEncoder()
		encoder.SetConfig(&encoder.Config{MinMax: true})
		selection = nil
		if projected {
			Select(&Modbus{}, "CommunityID,Payload,Payload")
			selection = append(selection, -1, len(fieldsModbus))
		}
		for i := range 10000 {
			a := &Modbus{
				Timestamp: int64(i), TransactionID: int32(i),
				Payload: []byte("payload-" + strconv.Itoa(i)), CommunityID: "flow-" + strconv.Itoa(i),
				SrcIP: "source-" + strconv.Itoa(i), DstIP: "destination-" + strconv.Itoa(i),
				Transport: strconv.Itoa(i), MessageRole: strconv.Itoa(i), ParseStatus: strconv.Itoa(i),
				ParseError: strconv.Itoa(i), Bank: strconv.Itoa(i), CorrelationStatus: strconv.Itoa(i),
				Values: []uint32{uint32(i)}, WriteValues: []uint32{uint32(i)}, DiagnosticData: []byte(strconv.Itoa(i)),
				DeviceIDObjects: []*ModbusDeviceIDObject{{Value: []byte(strconv.Itoa(i))}},
				FileRecords:     []*ModbusFileRecord{{Values: []uint32{uint32(i)}}},
			}
			got := a.Encode()
			if len(got) != len(a.CSVHeader()) {
				t.Fatalf("projection length mismatch: %v", got)
			}
			if projected && (got[1] != got[2] || got[3] != "" || got[4] != "") {
				t.Fatalf("duplicate/invalid projection mismatch: %v", got)
			}
			for j, value := range got {
				if projected && j >= 3 {
					continue
				}
				if _, err := strconv.ParseFloat(value, 64); err != nil {
					t.Fatalf("non-numeric encoding: %q", value)
				}
			}
		}
		// Inspect without GetSummary, which would create missing columns itself.
		columns := reflect.ValueOf(modbusEncoder).Elem().FieldByName("columns")
		if projected && columns.Len() != 2 {
			t.Fatalf("excluded fields acquired summaries: %v", columns.MapKeys())
		}
		boundedFields := []string{fieldPayload, fieldCommunityID}
		if !projected {
			boundedFields = append(boundedFields, "Transport", "MessageRole", "ParseStatus", "ParseError", "Bank", "CorrelationStatus", "Values", "WriteValues", "DiagnosticData", "DeviceIDObjects", "FileRecords")
		}
		for _, field := range boundedFields {
			if !columns.MapIndex(reflect.ValueOf(field)).IsValid() {
				t.Fatalf("missing selected summary: %s", field)
			}
			summary := modbusEncoder.GetSummary(encoder.TypeNumeric, field)
			if summary.Typ != encoder.TypeNumeric || len(summary.UniqueStrings) != 0 || summary.Index != 0 {
				t.Fatalf("%s retained categorical state: %+v", field, summary)
			}
			if summary.Min < 0 || summary.Max > 65535 || summary.Min == summary.Max {
				t.Fatalf("%s hash range = [%v, %v]", field, summary.Min, summary.Max)
			}
		}
	}
	modbusEncoder = encoder.NewValueEncoder()
	encoder.SetConfig(&encoder.Config{ZScore: true})
	selection = nil
	Select(&Modbus{}, "FunctionCode,FunctionCode")
	got := (&Modbus{FunctionCode: 8}).Encode()
	if got[0] != got[1] {
		t.Fatalf("duplicate columns differ: %v", got)
	}
	if summary := modbusEncoder.GetSummary(encoder.TypeNumeric, fieldFunctionCode); summary.Mean != 4 {
		t.Fatalf("duplicate column updated summary more than once: mean = %v", summary.Mean)
	}
}
