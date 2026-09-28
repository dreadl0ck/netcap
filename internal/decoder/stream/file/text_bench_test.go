package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func BenchmarkAnalyzeFileContent(b *testing.B) {
	for _, tc := range []struct {
		name, filename string
		content        []byte
	}{
		{"HTML", "index.html", []byte("<!doctype html><html><body><h1>Welcome</h1><p>Network capture test page</p></body></html>")},
		{"JSON", "response.json", []byte(`{"status":"ok","items":[{"name":"netcap","version":27}],"message":"response received"}`)},
		{"UTF8", "readme.txt", []byte("Café résumé — network traffic analysis.\n")},
		{"ControlByte", "response.bin", []byte("service response\x00with an embedded NUL byte")},
		{"PNGMagic", "image.png", []byte("\x89PNG\r\n\x1a\nimage payload")},
		{"ZIPMagic", "archive.zip", []byte("PK\x03\x04archive payload")},
	} {
		for _, size := range []int{512, 4096} {
			data := make([]byte, size)
			for i := range data {
				data[i] = tc.content[i%len(tc.content)]
			}
			b.Run(fmt.Sprintf("%s/%d", tc.name, size), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					fileAnalysisResult = AnalyzeFile(data, tc.filename)
				}
			})
		}
	}
}

type benchmarkFile struct {
	name string
	data []byte
}

// NETCAP_BENCH_FILES accepts comma-separated absolute or module-relative file paths.
func benchmarkFiles(b *testing.B) []benchmarkFile {
	b.Helper()
	paths := os.Getenv("NETCAP_BENCH_FILES")
	if paths == "" {
		b.Skip("set NETCAP_BENCH_FILES to extracted file paths")
	}
	var files []benchmarkFile
	for _, path := range strings.Split(paths, ",") {
		input := path
		if !filepath.IsAbs(input) {
			input = filepath.Join("../../../..", input)
		}
		data, err := os.ReadFile(input)
		if err != nil {
			b.Fatal(err)
		}
		files = append(files, benchmarkFile{filepath.Base(path), data})
	}
	return files
}

func BenchmarkAnalyzeExtractedFiles(b *testing.B) {
	for _, file := range benchmarkFiles(b) {
		b.Run(file.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				fileAnalysisResult = AnalyzeFile(file.data, file.name)
			}
		})
	}
}
