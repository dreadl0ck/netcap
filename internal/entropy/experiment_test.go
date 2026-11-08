//go:build entropyexperiment

package entropy

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"testing"
)

func checkExperiment(t *testing.T, data []byte) {
	t.Helper()
	var want [256]int
	var goBanks, asmBanks experimentBanks
	for _, v := range data {
		want[v]++
	}
	histogramGo4(data, &goBanks)
	histogramARM64(data, &asmBanks)
	if goBanks != asmBanks {
		t.Fatalf("size %d: bank mismatch", len(data))
	}
	for i, count := range want {
		if got := asmBanks[0][i] + asmBanks[1][i] + asmBanks[2][i] + asmBanks[3][i]; got != count {
			t.Fatalf("size %d byte %d: count %d, want %d", len(data), i, got, count)
		}
	}
	wantEntropy := math.Float64bits(Bytes(data))
	for _, fn := range []func([]byte) float64{BytesGo4, BytesARM64} {
		if got := fn(data); math.Float64bits(got) != wantEntropy {
			t.Fatalf("size %d: entropy %.17g, want %.17g", len(data), got, math.Float64frombits(wantEntropy))
		}
	}
}

func TestExperiment(t *testing.T) {
	checkExperiment(t, nil)
	for v := range 256 {
		for _, n := range []int{1, 3, 4, 15, 16, 31, 32, 63, 64, 511, 512, 513, 1500, 16387} {
			checkExperiment(t, bytes.Repeat([]byte{byte(v)}, n))
		}
	}
	rng := rand.New(rand.NewSource(42))
	data := make([]byte, 65536+32)
	for trial := range 300 {
		_, _ = rng.Read(data)
		n := rng.Intn(65537)
		if trial < 128 {
			n = trial
		}
		for offset := range 16 {
			checkExperiment(t, data[offset:offset+n:offset+n])
		}
	}
	for _, distribution := range []string{"repeated", "text", "random"} {
		checkExperiment(t, entropyData(1<<20, distribution))
	}
	// Nonzero, wide counters catch truncation and verify additive kernel semantics.
	var goBanks experimentBanks
	for bank := range goBanks {
		for v := range goBanks[bank] {
			goBanks[bank][v] = int(^uint(0)>>16) + bank + v
		}
	}
	asmBanks := goBanks
	histogramGo4(data, &goBanks)
	histogramARM64(data, &asmBanks)
	if goBanks != asmBanks {
		t.Fatal("nonzero bank mismatch")
	}
	for _, n := range []int{0, 1, 64, 512, 1500, 16384, 1 << 20} {
		data := entropyData(n, "random")
		for _, fn := range []func([]byte) float64{BytesGo4, BytesARM64} {
			if allocs := testing.AllocsPerRun(20, func() { entropySink = fn(data) }); allocs != 0 {
				t.Fatalf("size %d: %g allocations", n, allocs)
			}
		}
	}
}

func FuzzExperiment(f *testing.F) {
	for _, n := range []int{0, 1, 3, 4, 15, 16, 31, 32, 63, 64, 512, 1500, 16384} {
		f.Add(entropyData(n, "random"))
		f.Add(entropyData(n, "repeated"))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		checkExperiment(t, data)
	})
}

// Full entropy: all candidates include stack zeroing, merging, and exact logs.
// go test -tags entropyexperiment -run '^$' -bench '^BenchmarkExperiment$' -benchtime=300ms -count=3 -cpu=1
func BenchmarkExperiment(b *testing.B) {
	for _, n := range []int{0, 1, 15, 16, 31, 32, 63, 64, 512, 1500, 16384, 1 << 20} {
		for _, distribution := range []string{"repeated", "text", "random"} {
			data := entropyData(n, distribution)
			for _, impl := range []struct {
				name string
				fn   func([]byte) float64
			}{{"Bytes", Bytes}, {"Go4", BytesGo4}, {experimentASMName, BytesARM64}} {
				b.Run(fmt.Sprintf("%d/%s/%s", n, distribution, impl.name), func(b *testing.B) {
					b.SetBytes(int64(n))
					b.ReportAllocs()
					for b.Loop() {
						entropySink = impl.fn(data)
					}
				})
			}
		}
	}
}
