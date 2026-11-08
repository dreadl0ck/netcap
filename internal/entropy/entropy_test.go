package entropy

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"testing"
)

const entropyTolerance = 1e-12

var entropySink float64

func TestBytes(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for _, tc := range []struct {
		name string
		data []byte
		want float64
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"singleton", []byte{255}, 0},
		{"repeated", bytes.Repeat([]byte{42}, 4096), 0},
		{"balanced", bytes.Repeat([]byte{0, 255}, 128), 1},
		{"all256", all, 8},
		{"skewed", []byte{0, 0, 0, 255}, -0.75*math.Log2(0.75) - 0.25*math.Log2(0.25)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Bytes(tc.data); math.IsNaN(got) || math.Abs(got-tc.want) > entropyTolerance {
				t.Fatalf("Bytes = %.17g, want %.17g", got, tc.want)
			}
			if allocs := testing.AllocsPerRun(100, func() { entropySink = Bytes(tc.data) }); allocs != 0 {
				t.Errorf("Bytes allocated %g times, want zero", allocs)
			}
		})
	}
}

func TestBytesRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := range 200 {
		data := make([]byte, rng.Intn(64*1024+1))
		alphabet := 1 + rng.Intn(256)
		for j := range data {
			data[j] = byte(rng.Intn(alphabet))
		}
		got, want := Bytes(data), repeatedCountEntropy(data)
		if math.IsNaN(got) || math.Abs(got-want) > entropyTolerance {
			t.Fatalf("case %d (size %d, alphabet %d): Bytes = %.17g, want %.17g", i, len(data), alphabet, got, want)
		}
	}
}

func FuzzBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{255})
	f.Add(bytes.Repeat([]byte{42}, 512))
	f.Add([]byte{0, 255, 0, 255})
	f.Add([]byte{0, 0, 0, 255})
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	f.Add(all)
	f.Add(entropyData(1500, "text"))
	f.Add(entropyData(64*1024, "random"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}
		got, want := Bytes(data), repeatedCountEntropy(data)
		if math.IsNaN(got) || math.Abs(got-want) > entropyTolerance {
			t.Fatalf("size %d: Bytes = %.17g, want %.17g", len(data), got, want)
		}
	})
}

// repeatedCountEntropy is the old packet implementation and differential reference.
func repeatedCountEntropy(data []byte) (entropy float64) {
	if len(data) == 0 {
		return 0
	}
	for i := range 256 {
		p := float64(bytes.Count(data, []byte{byte(i)})) / float64(len(data))
		if p > 0 {
			entropy += -p * math.Log2(p)
		}
	}
	return entropy
}

func protobufMapEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func entropyData(size int, distribution string) []byte {
	data := make([]byte, size)
	switch distribution {
	case "repeated":
		for i := range data {
			data[i] = 42
		}
	case "text":
		const text = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nThe quick brown fox jumps over the lazy dog.\n"
		for i := range data {
			data[i] = text[i%len(text)]
		}
	case "random":
		rng := rand.New(rand.NewSource(1))
		for i := range data {
			data[i] = byte(rng.Intn(256))
		}
	default:
		panic("unknown entropy distribution: " + distribution)
	}
	return data
}

func BenchmarkBytes(b *testing.B) {
	for _, size := range []int{64, 512, 1500, 16384, 1 << 20} {
		for _, distribution := range []string{"repeated", "text", "random"} {
			data := entropyData(size, distribution)
			for _, impl := range []struct {
				name string
				fn   func([]byte) float64
			}{
				{"Bytes", Bytes},
				{"OldPacketRepeatedCount", repeatedCountEntropy},
				{"OldProtobufMap", protobufMapEntropy},
			} {
				b.Run(fmt.Sprintf("%d/%s/%s", size, distribution, impl.name), func(b *testing.B) {
					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					for b.Loop() {
						entropySink = impl.fn(data)
					}
				})
			}
		}
	}
}
