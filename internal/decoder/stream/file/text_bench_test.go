package file

import (
	"fmt"
	"testing"
)

var fileAnalysisResult *FileAnalysis

func BenchmarkAnalyzeFileText(b *testing.B) {
	for _, size := range []int{128, 512, 4096} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte('a' + i%26)
		}
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				fileAnalysisResult = AnalyzeFile(data, "sample.txt")
			}
		})
	}
}
