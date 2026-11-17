package file

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

type artifactData struct {
	bytes    []byte
	file     *os.File
	size     int64
	hashes   FileHashes
	mime     string
	accurate bool
	prefix   []byte
	facts    *artifactFacts
}

func (a *artifactData) Size() int64 {
	if a.file == nil {
		return int64(len(a.bytes))
	}
	return a.size
}
func (a *artifactData) Reader() io.Reader {
	if a.file == nil {
		return bytes.NewReader(a.bytes)
	}
	return io.NewSectionReader(a.file, 0, a.size)
}
func (a *artifactData) Hashes() (FileHashes, error) {
	if a.hashes.SHA256 != "" {
		return a.hashes, nil
	}
	if a.file == nil {
		a.hashes = ComputeHashes(a.bytes)
		return a.hashes, nil
	}
	return FileHashes{}, fmt.Errorf("stored artifact lacks verified hashes")
}
func (a *artifactData) Detect() (string, bool) {
	if a.file == nil {
		return DetectContentType(a.bytes)
	}
	return a.mime, a.accurate
}
func (a *artifactData) Analyze(name string) (*FileAnalysis, error) {
	if a.file == nil {
		return AnalyzeFile(a.bytes, name), nil
	}
	return a.facts.analyze(a.file, name)
}

func (a *artifactData) AnalyzerBytes() ([]byte, func(), error) {
	if a.file == nil {
		return a.bytes, func() {}, nil
	}
	if err := reserveBuffer(a.size); err != nil {
		return nil, func() {}, err
	}
	var once sync.Once
	release := func() { once.Do(func() { releaseBuffer(a.size) }) }
	data := make([]byte, int(a.size))
	_, err := io.ReadFull(io.NewSectionReader(a.file, 0, a.size), data)
	if err != nil {
		release()
		return nil, func() {}, err
	}
	return data, release, nil
}
