//go:build goexperiment.simd

package file

import (
	"math/bits"
	"simd"
)

func isTextFile(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	total := min(len(data), 512)
	data = data[:total]
	width := (simd.Uint8s{}).Len()
	if total < width {
		return isTextFileScalar(data)
	}

	var words [8]uint64 // 512 bits, the largest vector size in Go 1.27.
	var bad int
	for len(data) >= width {
		x := simd.LoadUint8s(data[:width]).BitsToInt8()
		mask := x.Less(simd.BroadcastInt8s(9)).And(x.GreaterEqual(simd.BroadcastInt8s(0))).
			Or(x.Greater(simd.BroadcastInt8s(13)).And(x.Less(simd.BroadcastInt8s(32)))).
			Or(x.Equal(simd.BroadcastInt8s(127)))
		mask.ToInt8s().ToBits().ReshapeToUint64s().Store(words[:])
		for _, word := range words[:width/8] {
			bad += bits.OnesCount64(word & 0x0101010101010101)
		}
		data = data[width:]
	}
	for _, b := range data {
		if b < 9 || (b > 13 && b < 32) || b == 127 {
			bad++
		}
	}
	return float64(bad)/float64(total) < 0.05
}
