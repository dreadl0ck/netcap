//go:build entropyexperiment

package entropy

import "math"

// Four banks reduce repeated-byte dependencies but add setup and merging work.
type experimentBanks [4][256]int

func histogramGo4(data []byte, banks *experimentBanks) {
	for len(data) >= 4 {
		banks[0][data[0]]++
		banks[1][data[1]]++
		banks[2][data[2]]++
		banks[3][data[3]]++
		data = data[4:]
	}
	for _, v := range data {
		banks[0][v]++
	}
}

func experimentEntropy(banks *experimentBanks, size int) float64 {
	var result float64
	for i, count := range banks[0] {
		count += banks[1][i] + banks[2][i] + banks[3][i]
		if count > 0 {
			p := float64(count) / float64(size)
			result -= p * math.Log2(p)
		}
	}
	return result
}

// BytesGo4 evaluates the portable four-bank experiment, including setup and logs.
func BytesGo4(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var banks experimentBanks
	histogramGo4(data, &banks)
	return experimentEntropy(&banks, len(data))
}
