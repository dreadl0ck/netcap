//go:build goexperiment.simd

package file

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestSIMDTextClassification(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for _, size := range []int{0, 1, 15, 16, 19, 20, 31, 32, 63, 64, 127, 511, 512, 513, 1024} {
		for run := range 100 {
			data := make([]byte, size)
			for _, mode := range []string{"random", "text", "threshold"} {
				for i := range data {
					switch mode {
					case "random":
						data[i] = byte(rng.Intn(256))
					case "text":
						data[i] = byte('a' + rng.Intn(26))
					case "threshold":
						data[i] = 'a'
						if i%20 == 0 {
							data[i] = byte(rng.Intn(33))
						}
					}
				}
				if got, want := isTextFile(data), isTextFileScalar(data); got != want {
					t.Fatalf("size %d run %d mode %s: got %v want %v", size, run, mode, got, want)
				}
			}
		}
	}
	for c := range 256 {
		data := make([]byte, 512)
		for i := range data {
			data[i] = byte(c)
		}
		if got, want := isTextFile(data), isTextFileScalar(data); got != want {
			t.Fatalf("repeated byte %d: got %v want %v", c, got, want)
		}
	}
	for _, length := range []int{20, 128, 512} {
		for _, badByte := range []byte{0, 8, 14, 31, 127} {
			for count := 0; count <= length/20+1; count++ {
				data := make([]byte, length)
				for i := range data {
					data[i] = 'a'
				}
				for i := range count {
					data[i] = badByte
				}
				if got, want := isTextFile(data), isTextFileScalar(data); got != want {
					t.Fatalf("length %d bad byte %d count %d: got %v want %v", length, badByte, count, got, want)
				}
			}
		}
	}
}

var textResult bool

func BenchmarkTextClassification(b *testing.B) {
	for _, size := range []int{32, 128, 512, 65536} {
		for _, kind := range []string{"ascii", "binary"} {
			data := make([]byte, size)
			for i := range data {
				if kind == "ascii" {
					data[i] = byte('a' + i%26)
				} else {
					data[i] = byte(i * 31)
				}
			}
			for _, impl := range []struct {
				name string
				fn   func([]byte) bool
			}{{"scalar", isTextFileScalar}, {"simd", isTextFile}} {
				b.Run(fmt.Sprintf("%d/%s/%s", size, kind, impl.name), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						textResult = impl.fn(data)
					}
				})
			}
		}
	}
}
