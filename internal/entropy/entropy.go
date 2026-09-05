// Package entropy calculates Shannon entropy over byte distributions.
package entropy

import "math"

// Bytes returns Shannon entropy in bits per byte, or zero for empty input.
func Bytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	var result float64
	length := float64(len(data))
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / length
			result -= p * math.Log2(p)
		}
	}
	return result
}
