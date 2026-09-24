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

package dnp3

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

// Every range specifier's field width. Conflating 0x00 with 0x01, or 0x07 with
// 0x08, shifts every later object header in the same fragment by two bytes.
func TestRangeFieldSize(t *testing.T) {
	for spec, want := range map[byte]int{
		0x0: 2, 0x1: 4, 0x2: 8,
		0x3: 2, 0x4: 4, 0x5: 8,
		0x6: 0,
		0x7: 1, 0x8: 2, 0x9: 4,
		0xA: -1, 0xB: 1, 0xC: -1, 0xD: -1, 0xE: -1, 0xF: -1,
	} {
		if got := rangeFieldSize(spec); got != want {
			t.Errorf("rangeFieldSize(%#x) = %d, want %d", spec, got, want)
		}
	}
}

func TestPrefixSize(t *testing.T) {
	for code, want := range map[byte]int{0: 0, 1: 1, 2: 2, 3: 4, 4: 1, 5: 2, 6: 4, 7: -1} {
		if got := prefixSize(code); got != want {
			t.Errorf("prefixSize(%d) = %d, want %d", code, got, want)
		}
	}
}

// The regression the decoder was rewritten for: object values must be stepped
// over, or the next header is read out of the previous object's data.
func TestObjectDataIsSkipped(t *testing.T) {
	msg := &types.DNP3{}

	// Binary Input variation 2 (1 octet each) for indexes 0..1, then Analog
	// Input variation 4 (2 octets) for index 0.
	data := []byte{
		1, 2, 0x00, 0, 1, 0x81, 0x01,
		30, 4, 0x00, 0, 0, 0x34, 0x12,
	}

	if !parseObjects(msg, data, true) {
		t.Fatal("parsing stopped early")
	}
	if len(msg.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(msg.Objects))
	}
	if msg.Objects[1].ObjectGroup != 30 || msg.Objects[1].Variation != 4 {
		t.Errorf("second header = group %d variation %d, want 30/4",
			msg.Objects[1].ObjectGroup, msg.Objects[1].Variation)
	}
}

// A 2-octet start/stop pair (0x01) is four bytes, not two.
func TestTwoOctetStartStop(t *testing.T) {
	msg := &types.DNP3{}

	data := []byte{
		1, 2, 0x01, 0x00, 0x01, 0x02, 0x01, // indexes 256..258
	}
	data = append(data, 0, 0, 0) // three 1-octet values

	if !parseObjects(msg, data, true) {
		t.Fatal("parsing stopped early")
	}

	obj := msg.Objects[0]
	if obj.StartIndex != 256 || obj.StopIndex != 258 || obj.Count != 3 {
		t.Errorf("start=%d stop=%d count=%d, want 256/258/3", obj.StartIndex, obj.StopIndex, obj.Count)
	}
}

// A 2-octet count (0x08) is two bytes. Reading one leaves the parser one byte
// inside the count field.
func TestTwoOctetCount(t *testing.T) {
	msg := &types.DNP3{}

	data := []byte{
		1, 2, 0x08, 0x02, 0x00, // count 2, no per-object prefix
		0x00, 0x00,
	}

	if !parseObjects(msg, data, true) {
		t.Fatal("parsing stopped early")
	}
	if msg.Objects[0].Count != 2 {
		t.Errorf("count = %d, want 2", msg.Objects[0].Count)
	}
}

// Packed variations size the whole run, not each object.
func TestPackedVariationRunLength(t *testing.T) {
	msg := &types.DNP3{}

	// Binary Input variation 1, indexes 0..15: sixteen bits, two octets.
	data := []byte{1, 1, 0x00, 0, 15, 0xAA, 0x55, 30, 4, 0x06}

	if !parseObjects(msg, data, true) {
		t.Fatal("parsing stopped early")
	}
	if len(msg.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(msg.Objects))
	}
	if msg.Objects[1].ObjectGroup != 30 {
		t.Errorf("second header = group %d, want 30", msg.Objects[1].ObjectGroup)
	}
}

// An unsizable header stops the walk, and is not itself reported: at that point
// the bytes are as likely to be the previous object's values as a header.
func TestUnknownVariationStopsParsing(t *testing.T) {
	msg := &types.DNP3{}

	data := []byte{
		200, 99, 0x00, 0, 0, // no shape for group 200
		1, 2, 0x06,
	}

	if parseObjects(msg, data, true) {
		t.Fatal("parsing continued past an unsizable object")
	}
	if len(msg.Objects) != 0 {
		t.Errorf("reported %d objects from a header it could not size", len(msg.Objects))
	}
}

// A header that sized correctly was really sent, even when its values are cut
// off, so it is kept.
func TestTruncatedRunKeepsSizedHeader(t *testing.T) {
	msg := &types.DNP3{}

	// Analog Input variation 4 is two octets each; three are claimed and one
	// is present.
	data := []byte{30, 4, 0x00, 0, 2, 0x34, 0x12}

	if parseObjects(msg, data, true) {
		t.Fatal("parsing continued past a truncated run")
	}
	if len(msg.Objects) != 1 {
		t.Fatalf("got %d objects, want the header that sized correctly", len(msg.Objects))
	}
	if msg.Objects[0].ObjectGroup != 30 {
		t.Errorf("kept header = group %d, want 30", msg.Objects[0].ObjectGroup)
	}
}

// A read names points and carries no values, so headers follow one another.
func TestReadRequestHeadersHaveNoData(t *testing.T) {
	msg := &types.DNP3{}

	// The Class 1/2/3 poll from the capture corpus: 3C 02 06, 3C 03 06, 3C 04 06
	data := []byte{0x3C, 2, 0x06, 0x3C, 3, 0x06, 0x3C, 4, 0x06}

	if !parseObjects(msg, data, false) {
		t.Fatal("parsing stopped early")
	}
	if len(msg.Objects) != 3 {
		t.Fatalf("got %d objects, want 3", len(msg.Objects))
	}
	for i, o := range msg.Objects {
		if o.ObjectGroup != groupClassData || o.Variation != int32(i+2) {
			t.Errorf("object %d = group %d variation %d", i, o.ObjectGroup, o.Variation)
		}
	}
}

// The Class 0 integrity poll returns the outstation's whole static point map.
// Naming it the same as a routine event poll hides that distinction.
func TestClassDataNamesDistinguishVariations(t *testing.T) {
	if got := objectName(groupClassData, 0); got != "Class 0 Data (static point map)" {
		t.Errorf("group 60 variation 0 = %q", got)
	}
	for _, v := range []int32{1, 2, 3} {
		want := "Class " + string(rune('0'+v)) + " Data"
		if got := objectName(groupClassData, v); got != want {
			t.Errorf("group 60 variation %d = %q, want %q", v, got, want)
		}
	}
}

// Trip and close are the two outcomes that matter, and they differ by two bits
// of one octet.
func TestCROBControlCodeNames(t *testing.T) {
	for _, tt := range []struct {
		code byte
		name string
	}{
		{0x01, "PULSE_ON"},
		{0x03, "LATCH_ON"},
		{0x04, "LATCH_OFF"},
		{0x41, "PULSE_ON/CLOSE"},
		{0x81, "PULSE_ON/TRIP"},
		{0x83, "LATCH_ON/TRIP"},
	} {
		msg := &types.DNP3{}

		data := []byte{12, 1, 0x17, 1, 7, tt.code, 1, 100, 0, 0, 0, 200, 0, 0, 0, 0}
		if !parseObjects(msg, data, true) {
			t.Fatalf("code %#02x: parsing stopped early", tt.code)
		}

		blocks := msg.Objects[0].ControlBlocks
		if len(blocks) != 1 {
			t.Fatalf("code %#02x: got %d control blocks", tt.code, len(blocks))
		}

		c := blocks[0]
		if c.ControlCodeName != tt.name {
			t.Errorf("code %#02x: name = %q, want %q", tt.code, c.ControlCodeName, tt.name)
		}
		if c.Index != 7 || c.Count != 1 || c.OnTime != 100 || c.OffTime != 200 {
			t.Errorf("code %#02x: index=%d count=%d on=%d off=%d", tt.code, c.Index, c.Count, c.OnTime, c.OffTime)
		}
	}
}

// With no per-object index prefix, the index comes from the range's start.
func TestCROBIndexFromRange(t *testing.T) {
	msg := &types.DNP3{}

	data := []byte{12, 1, 0x00, 5, 5, 0x41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !parseObjects(msg, data, true) {
		t.Fatal("parsing stopped early")
	}

	blocks := msg.Objects[0].ControlBlocks
	if len(blocks) != 1 || blocks[0].Index != 5 {
		t.Fatalf("index not taken from the range start: %+v", blocks)
	}
}

// A run that claims more objects than the fragment holds must not be decoded
// from whatever follows.
func TestTruncatedCROBRunRejected(t *testing.T) {
	msg := &types.DNP3{}

	// Count says two control blocks; only one fits.
	data := []byte{12, 1, 0x17, 2, 7, 0x41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	if parseObjects(msg, data, true) {
		t.Fatal("parsing continued past a truncated run")
	}
	for _, o := range msg.Objects {
		if len(o.ControlBlocks) != 0 {
			t.Errorf("decoded %d control blocks from a truncated run", len(o.ControlBlocks))
		}
	}
}

// A stop index below the start is not a range, so the header is not reported.
// The old decoder published it with a negative count.
func TestInvalidRangeRejected(t *testing.T) {
	msg := &types.DNP3{}

	if parseObjects(msg, []byte{1, 2, 0x00, 5, 1}, true) {
		t.Fatal("accepted a stop index below the start")
	}
	if len(msg.Objects) != 0 {
		t.Errorf("reported %d objects from an invalid range", len(msg.Objects))
	}
}

// "All objects" carries no range field and no values.
func TestAllObjectsQualifier(t *testing.T) {
	msg := &types.DNP3{}

	if !parseObjects(msg, []byte{60, 1, 0x06}, true) {
		t.Fatal("parsing stopped early")
	}
	if msg.Objects[0].Count != -1 {
		t.Errorf("count = %d, want -1 for all objects", msg.Objects[0].Count)
	}
}

func TestCarriesObjectData(t *testing.T) {
	for _, fc := range []int32{FuncWrite, FuncSelect, FuncOperate, FuncDirectOperate, FuncResponse, FuncUnsolicitedResponse} {
		if !carriesObjectData(fc) {
			t.Errorf("function %d should carry object data", fc)
		}
	}
	for _, fc := range []int32{FuncRead, FuncEnableUnsolicited, FuncDisableUnsolicited, FuncAssignClass, FuncColdRestart} {
		if carriesObjectData(fc) {
			t.Errorf("function %d should not carry object data", fc)
		}
	}
}
