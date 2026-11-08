//go:build entropyexperiment && !purego

package entropy

const experimentASMName = "ASM4"

//go:noescape
func histogramARM64(data []byte, banks *experimentBanks)

// BytesARM64 evaluates scalar four-bank ARM64 assembly, including setup and logs.
func BytesARM64(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var banks experimentBanks
	histogramARM64(data, &banks)
	return experimentEntropy(&banks, len(data))
}
