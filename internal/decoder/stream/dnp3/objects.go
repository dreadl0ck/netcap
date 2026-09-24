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
	"encoding/binary"
	"math"
	"strconv"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// Object groups worth naming. Group 12 is the one that moves breakers.
const (
	groupBinaryInput        = 1
	groupBinaryInputEvent   = 2
	groupDoubleBitInput     = 3
	groupBinaryOutput       = 10
	groupBinaryOutputEvent  = 11
	groupCROB               = 12
	groupBinaryOutputCmdEvt = 13
	groupCounter            = 20
	groupFrozenCounter      = 21
	groupAnalogInput        = 30
	groupAnalogInputEvent   = 32
	groupAnalogOutputStatus = 40
	groupAnalogOutputBlock  = 41
	groupTimeAndDate        = 50
	groupClassData          = 60
	groupFileControl        = 70
	groupInternalIndication = 80
	groupOctetString        = 110
	groupOctetStringEvent   = 111
	groupAuthentication     = 120
)

// qualifier field layout: reserved(7) | prefix code(6-4) | range specifier(3-0).
const (
	qualifierPrefixNone   = 0
	qualifierPrefixIndex1 = 1
	qualifierPrefixIndex2 = 2
	qualifierPrefixIndex4 = 3
	qualifierPrefixSize1  = 4
	qualifierPrefixSize2  = 5
	qualifierPrefixSize4  = 6

	qualifierRangeStartStop1 = 0x0
	qualifierRangeStartStop2 = 0x1
	qualifierRangeStartStop4 = 0x2
	qualifierRangeVirtual1   = 0x3
	qualifierRangeVirtual2   = 0x4
	qualifierRangeVirtual4   = 0x5
	qualifierRangeAll        = 0x6
	qualifierRangeCount1     = 0x7
	qualifierRangeCount2     = 0x8
	qualifierRangeCount4     = 0x9
	qualifierRangeVariable   = 0xB
)

// prefixSize returns the octets each object is prefixed with, or -1 for a
// reserved code.
func prefixSize(code byte) int {
	switch code {
	case qualifierPrefixNone:
		return 0
	case qualifierPrefixIndex1, qualifierPrefixSize1:
		return 1
	case qualifierPrefixIndex2, qualifierPrefixSize2:
		return 2
	case qualifierPrefixIndex4, qualifierPrefixSize4:
		return 4
	}

	return -1
}

// prefixIsIndex reports whether the prefix carries a point index rather than an
// object size.
func prefixIsIndex(code byte) bool {
	return code >= qualifierPrefixIndex1 && code <= qualifierPrefixIndex4
}

// rangeFieldSize returns the octets the range field occupies, or -1 for a
// reserved specifier.
//
// Conflating the widths here is what silently corrupts every later object in
// the same fragment: specifier 0x01 is a 2-octet start and stop, not a 1-octet
// pair, and 0x08 is a 2-octet count, not a 1-octet one.
func rangeFieldSize(spec byte) int {
	switch spec {
	case qualifierRangeStartStop1, qualifierRangeVirtual1:
		return 2
	case qualifierRangeStartStop2, qualifierRangeVirtual2:
		return 4
	case qualifierRangeStartStop4, qualifierRangeVirtual4:
		return 8
	case qualifierRangeAll:
		return 0
	case qualifierRangeCount1, qualifierRangeVariable:
		return 1
	case qualifierRangeCount2:
		return 2
	case qualifierRangeCount4:
		return 4
	}

	return -1
}

// objectShape describes the wire size of one object of a given variation.
// bits is nonzero for bit-packed variations, where the run is sized as a whole
// rather than per object.
type objectShape struct {
	size int
	bits int
}

var unknownShape = objectShape{size: -1}

// objectShapeFor returns the encoded size for a group and variation.
// An unknown pair stops object parsing rather than guessing a stride.
//
//nolint:gocyclo,cyclop,funlen // a wire-format lookup table; splitting it hides the shape
func objectShapeFor(group, variation int32) objectShape {
	switch group {
	case groupBinaryInput:
		switch variation {
		case 1:
			return objectShape{bits: 1}
		case 2:
			return objectShape{size: 1}
		}
	case groupBinaryInputEvent, groupBinaryOutputEvent, groupBinaryOutputCmdEvt:
		switch variation {
		case 1:
			return objectShape{size: 1}
		case 2:
			return objectShape{size: 7}
		case 3:
			return objectShape{size: 3}
		}
	case groupDoubleBitInput:
		switch variation {
		case 1:
			return objectShape{bits: 2}
		case 2:
			return objectShape{size: 1}
		}
	case 4: // Double-bit Binary Input Event
		switch variation {
		case 1:
			return objectShape{size: 1}
		case 2:
			return objectShape{size: 7}
		case 3:
			return objectShape{size: 3}
		}
	case groupBinaryOutput:
		switch variation {
		case 1:
			return objectShape{bits: 1}
		case 2:
			return objectShape{size: 1}
		}
	case groupCROB:
		switch variation {
		case 1, 2:
			return objectShape{size: crobLen}
		case 3:
			return objectShape{bits: 1}
		}
	case groupCounter, groupAnalogOutputStatus, groupAnalogOutputBlock:
		switch variation {
		case 1, 3:
			return objectShape{size: 5}
		case 2, 4:
			return objectShape{size: 3}
		case 5:
			return objectShape{size: 5}
		case 6:
			return objectShape{size: 9}
		}
	case groupFrozenCounter, 22, 23:
		switch variation {
		case 1:
			return objectShape{size: 5}
		case 2:
			return objectShape{size: 3}
		case 5:
			return objectShape{size: 11}
		case 6:
			return objectShape{size: 9}
		case 9:
			return objectShape{size: 4}
		case 10:
			return objectShape{size: 2}
		}
	case groupAnalogInput, 31:
		switch variation {
		case 1:
			return objectShape{size: 5}
		case 2:
			return objectShape{size: 3}
		case 3:
			return objectShape{size: 4}
		case 4:
			return objectShape{size: 2}
		case 5:
			return objectShape{size: 5}
		case 6:
			return objectShape{size: 9}
		}
	case groupAnalogInputEvent, 33, 42, 43:
		switch variation {
		case 1:
			return objectShape{size: 5}
		case 2:
			return objectShape{size: 3}
		case 3:
			return objectShape{size: 11}
		case 4:
			return objectShape{size: 9}
		case 5:
			return objectShape{size: 5}
		case 6:
			return objectShape{size: 9}
		case 7:
			return objectShape{size: 11}
		case 8:
			return objectShape{size: 15}
		}
	case 34: // Analog Input Deadband
		switch variation {
		case 1:
			return objectShape{size: 2}
		case 2, 3:
			return objectShape{size: 4}
		}
	case groupTimeAndDate:
		switch variation {
		case 1, 3:
			return objectShape{size: 6}
		case 2:
			return objectShape{size: 10}
		case 4:
			return objectShape{size: 11}
		}
	case 51: // Time and Date CTO
		return objectShape{size: 6}
	case 52: // Time Delay
		return objectShape{size: 2}
	case groupClassData:
		// A class reference names data, it does not carry any.
		return objectShape{size: 0}
	case groupInternalIndication:
		if variation == 1 {
			return objectShape{bits: 1}
		}
	case groupOctetString, groupOctetStringEvent:
		// The variation is the string length.
		if variation > 0 && variation <= 255 {
			return objectShape{size: int(variation)}
		}
	}

	return unknownShape
}

// objectName names a group and variation. The variation matters: group 60
// variation 0 is the Class 0 static point map, which is an inventory of the
// outstation, while variations 1 to 3 are routine event polls.
//
//nolint:gocyclo,cyclop,funlen // a wire-format lookup table; splitting it hides the shape
func objectName(group, variation int32) string {
	switch group {
	case groupBinaryInput:
		return "Binary Input"
	case groupBinaryInputEvent:
		return "Binary Input Event"
	case groupDoubleBitInput:
		return "Double-bit Binary Input"
	case 4:
		return "Double-bit Binary Input Event"
	case groupBinaryOutput:
		return "Binary Output"
	case groupBinaryOutputEvent:
		return "Binary Output Event"
	case groupCROB:
		return "Control Relay Output Block (CROB)"
	case groupBinaryOutputCmdEvt:
		return "Binary Output Command Event"
	case groupCounter:
		return "Counter"
	case groupFrozenCounter:
		return "Frozen Counter"
	case 22:
		return "Counter Event"
	case 23:
		return "Frozen Counter Event"
	case groupAnalogInput:
		return "Analog Input"
	case 31:
		return "Frozen Analog Input"
	case groupAnalogInputEvent:
		return "Analog Input Event"
	case 33:
		return "Frozen Analog Input Event"
	case 34:
		return "Analog Input Deadband"
	case groupAnalogOutputStatus:
		return "Analog Output Status"
	case groupAnalogOutputBlock:
		return "Analog Output Block"
	case 42:
		return "Analog Output Event"
	case 43:
		return "Analog Output Command Event"
	case groupTimeAndDate:
		return "Time and Date"
	case 51:
		return "Time and Date CTO"
	case 52:
		return "Time Delay"
	case groupClassData:
		switch variation {
		case 0:
			return "Class 0 Data (static point map)"
		case 1, 2, 3:
			return "Class " + strconv.Itoa(int(variation)) + " Data"
		}

		return "Class Data"
	case groupFileControl:
		return "File Control"
	case groupInternalIndication:
		return "Internal Indications"
	case groupOctetString:
		return "Octet String"
	case groupOctetStringEvent:
		return "Octet String Event"
	case groupAuthentication:
		return "Secure Authentication"
	case 121, 122:
		return "Security Statistic"
	}

	return "Unknown"
}

// carriesObjectData reports whether objects in this request carry encoded
// values. A read names points, it does not supply them.
func carriesObjectData(fc int32) bool {
	switch fc {
	case FuncWrite, FuncSelect, FuncOperate, FuncDirectOperate, FuncDirectOperateNoAck,
		FuncResponse, FuncUnsolicitedResponse,
		FuncAuthenticateReq, FuncAuthenticateReqNoAck, FuncAuthenticateResp:
		return true
	}

	return false
}

// readUint reads a little-endian unsigned integer of n octets.
func readUint(b []byte, n int) uint32 {
	switch n {
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(b))
	case 4:
		return binary.LittleEndian.Uint32(b)
	}

	return 0
}

// parseObjects walks the object headers of an application fragment.
//
// It stops at the first header it cannot size, because continuing means reading
// the previous object's values as the next object's group and variation. That
// is how a CROB payload becomes three additional objects that were never sent.
// Returns false when parsing stopped early.
func parseObjects(msg *types.DNP3, data []byte, withData bool) bool {
	offset := 0

	for offset+3 <= len(data) {
		obj := &types.DNP3Object{
			ObjectGroup: int32(data[offset]),
			Variation:   int32(data[offset+1]),
			Qualifier:   int32(data[offset+2]),
		}
		obj.ObjectName = objectName(obj.ObjectGroup, obj.Variation)

		qualifier := data[offset+2]
		prefix := qualifier >> 4 & 0x07
		spec := qualifier & 0x0F

		obj.PrefixCode = int32(prefix)
		obj.RangeSpecifier = int32(spec)

		offset += 3

		// A header that cannot be interpreted is not evidence that it was sent:
		// at this point the bytes are as likely to be the previous object's
		// values. Reporting it anyway is what turned a control block's payload
		// into objects from groups that do not exist.
		rangeLen := rangeFieldSize(spec)
		if rangeLen < 0 || offset+rangeLen > len(data) {
			return false
		}

		count, ok := decodeRange(obj, data[offset:offset+rangeLen], spec)
		if !ok {
			return false
		}

		offset += rangeLen

		if !withData || spec == qualifierRangeAll {
			// No values follow, so the next header starts here.
			msg.Objects = append(msg.Objects, obj)

			continue
		}

		n, ok := objectRunLen(obj, prefix, count)
		if !ok {
			return false
		}

		// The header sized correctly, so it was really sent even though its
		// values are cut off.
		msg.Objects = append(msg.Objects, obj)

		if offset+n > len(data) {
			return false
		}

		if obj.ObjectGroup == groupCROB && n > 0 {
			parseCROBRun(obj, data[offset:offset+n], prefix, count)
			nameControlPoints(msg, obj)
		}

		offset += n
	}

	return true
}

// decodeRange fills in the index or count fields and returns the number of
// objects the header describes.
//
// The 4-octet forms can carry values the int32 record fields cannot hold. Such
// a header is rejected rather than stored wrapped: a negative index reads as a
// decoded value, and no outstation has two billion points.
func decodeRange(obj *types.DNP3Object, b []byte, spec byte) (count int, ok bool) {
	switch spec {
	case qualifierRangeStartStop1, qualifierRangeStartStop2, qualifierRangeStartStop4,
		qualifierRangeVirtual1, qualifierRangeVirtual2, qualifierRangeVirtual4:
		half := len(b) / 2

		start, stop := readUint(b[:half], half), readUint(b[half:], half)
		if start > math.MaxInt32 || stop > math.MaxInt32 || stop < start {
			// A stop below the start is not a range; the older decoder reported
			// this as a negative count.
			return 0, false
		}

		obj.StartIndex, obj.StopIndex = int32(start), int32(stop)
		obj.Count = int32(stop - start + 1)

		return int(stop - start + 1), true

	case qualifierRangeAll:
		// Every object in the group. The count is not on the wire.
		obj.Count = -1

		return 0, true

	case qualifierRangeCount1, qualifierRangeCount2, qualifierRangeCount4, qualifierRangeVariable:
		n := readUint(b, len(b))
		if n > math.MaxInt32 {
			return 0, false
		}

		obj.Count = int32(n)

		return int(n), true
	}

	return 0, false
}

// objectRunLen returns the octets occupied by count objects, including their
// per-object prefixes.
func objectRunLen(obj *types.DNP3Object, prefix byte, count int) (int, bool) {
	if count <= 0 {
		return 0, true
	}

	pre := prefixSize(prefix)
	if pre < 0 {
		return 0, false
	}

	shape := objectShapeFor(obj.ObjectGroup, obj.Variation)

	if shape.bits > 0 {
		if pre != 0 {
			// Packed variations are not indexed per object.
			return 0, false
		}

		return (count*shape.bits + 7) / 8, true
	}

	if shape.size < 0 {
		return 0, false
	}

	return count * (pre + shape.size), true
}

// Control Relay Output Block, IEEE 1815 group 12 variation 1:
// control code, count, on time, off time, status.
const crobLen = 11

// Trip-close code, the high two bits of the control code.
const (
	crobTCCNul   = 0
	crobTCCClose = 1
	crobTCCTrip  = 2
)

// Operation type, the low four bits of the control code.
const (
	crobOpNul      = 0
	crobOpPulseOn  = 1
	crobOpPulseOff = 2
	crobOpLatchOn  = 3
	crobOpLatchOff = 4
)

// parseCROBRun decodes the control blocks in an object run. This is the field
// that says whether a breaker was told to close or to trip; without it a record
// shows only that some control was addressed.
func parseCROBRun(obj *types.DNP3Object, run []byte, prefix byte, count int) {
	if obj.Variation != 1 && obj.Variation != 2 {
		return
	}

	pre := prefixSize(prefix)
	if pre < 0 {
		return
	}

	stride := pre + crobLen

	for i := range count {
		off := i * stride
		if off+stride > len(run) {
			return
		}

		crob := &types.DNP3CROB{}
		body := run[off+pre:]

		if pre > 0 && prefixIsIndex(prefix) {
			crob.Index = int64(readUint(run[off:off+pre], pre))
		} else {
			crob.Index = int64(obj.StartIndex) + int64(i)
		}

		control := body[0]
		crob.ControlCode = int32(control)
		crob.TripCloseCode = int32(control >> 6 & 0x03)
		crob.Clear = control&0x20 != 0
		crob.Queue = control&0x10 != 0
		crob.OperationType = int32(control & 0x0F)
		crob.ControlCodeName = crobName(crob.TripCloseCode, crob.OperationType)
		crob.Count = int32(body[1])
		crob.OnTime = int64(binary.LittleEndian.Uint32(body[2:6]))
		crob.OffTime = int64(binary.LittleEndian.Uint32(body[6:10]))
		crob.StatusCode = int32(body[10])

		obj.ControlBlocks = append(obj.ControlBlocks, crob)
	}
}

// nameControlPoints resolves point indexes against the configured device
// profile. The outstation is keyed on the DNP3 link address rather than the IP:
// one address can be reached over several paths, and one IP can front several
// outstations.
//
// A command is addressed to Destination on a request and answered from Source
// on a response, so the outstation is whichever end is not the master.
func nameControlPoints(msg *types.DNP3, obj *types.DNP3Object) {
	outstation := msg.Destination
	if !msg.IsMaster {
		outstation = msg.Source
	}

	for _, c := range obj.ControlBlocks {
		c.PointName = decoderconfig.Instance.DNP3PointName(outstation, obj.ObjectGroup, c.Index)
	}
}

func crobName(tcc, op int32) string {
	name := ""

	switch op {
	case crobOpNul:
		name = "NUL"
	case crobOpPulseOn:
		name = "PULSE_ON"
	case crobOpPulseOff:
		name = "PULSE_OFF"
	case crobOpLatchOn:
		name = "LATCH_ON"
	case crobOpLatchOff:
		name = "LATCH_OFF"
	default:
		name = nameUnknown
	}

	switch tcc {
	case crobTCCClose:
		return name + "/CLOSE"
	case crobTCCTrip:
		return name + "/TRIP"
	}

	return name
}
