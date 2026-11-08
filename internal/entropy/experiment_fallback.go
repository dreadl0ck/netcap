//go:build entropyexperiment && (!arm64 || purego)

package entropy

const experimentASMName = "GoFallback"

func histogramARM64(data []byte, banks *experimentBanks) {
	histogramGo4(data, banks)
}

// BytesARM64 uses portable Go when ARM64 assembly is unavailable or disabled.
func BytesARM64(data []byte) float64 { return BytesGo4(data) }
