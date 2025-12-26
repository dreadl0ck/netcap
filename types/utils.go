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

package types

import (
	"hash/fnv"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/dreadl0ck/netcap/utils"
)

var (
	// StructureBegin marks the beginning of a structure in CSV.
	StructureBegin = ""

	// StructureEnd marks the end of a structure in CSV.
	StructureEnd = ""

	// FieldSeparator separates fields within a structure in CSV.
	FieldSeparator = ","
)

type stringer interface {
	toString() string
}

// panic: value method github.com/dreadl0ck/netcap/types.LSUpdate.ToString called using nil *LSUpdate pointer
// func toString(v stringer) string {
// 	if v != nil {
// 		return v.toString()
// 	}
// 	return ""
// }

// this function wraps the toString() function call with a nil pointer check.
func toString(c stringer) string {
	// make sure its not a nil pointer
	// a simple nil check is apparently not enough here
	if c == nil || (reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()) {
		return ""
	}

	// now check if the stringer interface is implemented
	if str, ok := c.(stringer); ok {
		return str.toString()
	}

	// in case the stringer interface is not implemented: fail
	spew.Dump(c)
	panic("toString called with an instance that does not implement the types.stringer interface")
}

func joinInts(a []int32) string {
	var (
		b         strings.Builder
		lastIndex = len(a) - 1
	)

	b.WriteString(StructureBegin)

	for i, num := range a {
		b.WriteString(formatInt32(num))

		if i != lastIndex {
			b.WriteString(FieldSeparator)
		}
	}

	b.WriteString(StructureEnd)

	return b.String()
}

func joinUints(a []uint32) string {
	var (
		b         strings.Builder
		lastIndex = len(a) - 1
	)

	b.WriteString(StructureBegin)

	for i, num := range a {
		b.WriteString(formatUint32(num))

		if i != lastIndex {
			b.WriteString(FieldSeparator)
		}
	}

	b.WriteString(StructureEnd)

	return b.String()
}

func join(a ...string) string {
	var (
		b         strings.Builder
		lastIndex = len(a) - 1
	)

	b.WriteString(StructureBegin)

	for i, v := range a {
		b.WriteString(v)

		if i != lastIndex {
			b.WriteString(FieldSeparator)
		}
	}

	b.WriteString(StructureEnd)

	return b.String()
}

func formatTimestamp(ts int64) string {
	if UTC {
		return utils.UnixTimeToUTC(ts)
	}

	return strconv.FormatInt(ts, 10)
}

func formatInt32(v int32) string {
	return strconv.FormatInt(int64(v), 10)
}

func formatInt64(v int64) string {
	return strconv.FormatInt(v, 10)
}

func formatUint32(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

func formatUint64(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func formatFloat64(v float64) string {
	return strconv.FormatFloat(v, 'f', 6, 64)
}

func ipToInt64(addr string) int64 {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}

	// For IPv4: convert 4 bytes directly to int64 (no information loss)
	if ip4 := ip.To4(); ip4 != nil {
		n := big.NewInt(0)
		n.SetBytes(ip4)
		return n.Int64()
	}

	// For IPv6: use FNV-1a hash to get a collision-resistant 64-bit value
	// This is necessary because IPv6 addresses are 128 bits and cannot fit in int64.
	// Using a hash ensures different IPv6 addresses produce different values with
	// high probability, avoiding the collision problem of using only lower 64 bits.
	ip6 := ip.To16()
	h := fnv.New64a()
	h.Write(ip6)
	return int64(h.Sum64())
}

func macToUint64(addr string) uint64 {

	var mac uint64
	for j, b := range strings.ReplaceAll(addr, ":", "") {
		if j >= 12 {
			break
		}
		mac <<= 12
		mac += uint64(b)
	}

	return mac
}

func portToInt(p string) int {
	n, _ := strconv.Atoi(p)
	return n
}

//func IP4ToUint32(ip string) uint32 {
//	return binary.LittleEndian.Uint32(net.ParseIP(ip).To4())
//}
