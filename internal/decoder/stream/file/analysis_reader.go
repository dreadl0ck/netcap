package file

import (
	"bytes"
	"io"
	"math"
	"path/filepath"
	"strings"
)

type artifactFacts struct {
	prefix    []byte
	counts    [256]int64
	tokens    map[string]bool
	firstLine map[string]bool
	lineDone  bool
	embedded  bool
	size      int64
}

var artifactTokens = []string{"param(", "$PSVersionTable", "function ", "cmdlet", "function(", "var ", "const ", "let ", "Sub ", "Function ", "End Sub", "EncryptedPackage", "StrongEncryptionDataSpace", ":"}
var firstLineTokens = []string{"python", "bash", "/sh", "perl", "ruby", "node"}

func (f *artifactFacts) feed(window []byte, overlap int) {
	data := window[overlap:]
	if f.tokens == nil {
		f.tokens = map[string]bool{}
		f.firstLine = map[string]bool{}
	}
	f.prefix = append(f.prefix, data[:min(len(data), 512-len(f.prefix))]...)
	for _, b := range data {
		f.counts[b]++
	}
	f.size += int64(len(data))
	f.embedded = f.embedded || hasEmbeddedScript(window)
	for _, token := range artifactTokens {
		f.tokens[token] = f.tokens[token] || bytes.Contains(window, []byte(token))
	}
	if !f.lineDone {
		line := window
		if at := bytes.IndexByte(line, '\n'); at >= 0 {
			line = line[:at]
			f.lineDone = true
		}
		for _, token := range firstLineTokens {
			f.firstLine[token] = f.firstLine[token] || bytes.Contains(line, []byte(token))
		}
	}
}

func (f *artifactFacts) scriptType() string {
	if bytes.HasPrefix(f.prefix, []byte("#!")) {
		for _, pair := range [][2]string{{"python", "text/x-python"}, {"bash", "text/x-shellscript"}, {"/sh", "text/x-shellscript"}, {"perl", "text/x-perl"}, {"ruby", "text/x-ruby"}, {"node", "application/javascript"}} {
			if f.firstLine[pair[0]] {
				return pair[1]
			}
		}
	}
	if f.tokens["param("] || f.tokens["$PSVersionTable"] || f.tokens["function "] && f.tokens["cmdlet"] {
		return "text/x-powershell"
	}
	if f.tokens["function("] || f.tokens["var "] || f.tokens["const "] || f.tokens["let "] {
		return "application/javascript"
	}
	if f.tokens["Sub "] || f.tokens["Function "] && f.tokens["End Sub"] {
		return "text/vbscript"
	}
	return ""
}

func (f *artifactFacts) mimeType() (string, bool) {
	typ, accurate := DetectContentType(f.prefix)
	if isTextContent(f.prefix) && bytes.HasPrefix(bytes.TrimSpace(f.prefix[:min(100, len(f.prefix))]), []byte("{")) && f.tokens[":"] && typ == "text/plain" {
		return "application/json", true
	}
	return typ, accurate
}

func (facts *artifactFacts) analyze(reader io.ReaderAt, name string) (*FileAnalysis, error) {
	a := &FileAnalysis{}
	if facts.size == 0 {
		return a, nil
	}
	a.MagicBytes = append([]byte(nil), facts.prefix[:min(8, len(facts.prefix))]...)
	a.TrueFileType = detectFileTypeFromMagic(facts.prefix)
	if facts.size >= 2 && isTextFile(facts.prefix) {
		matchedMagic := false
		for _, magic := range magicSignatures {
			matchedMagic = matchedMagic || bytes.HasPrefix(facts.prefix, magic)
		}
		if !matchedMagic {
			a.TrueFileType = facts.scriptType()
			if a.TrueFileType == "" {
				a.TrueFileType = "text/plain"
			}
		}
	}
	expected := extensionToMimeType(strings.ToLower(filepath.Ext(name)))
	a.TypeMismatch = expected != "" && a.TrueFileType != "" && !strings.HasPrefix(a.TrueFileType, expected) && !strings.HasPrefix(expected, a.TrueFileType)
	cfg := GetGlobalConfig().FileExtraction.Advanced
	if cfg.DetectExecutables {
		a.IsELFExecutable = isELFExecutable(facts.prefix)
		a.IsMachO = isMachOExecutable(facts.prefix)
		if len(facts.prefix) >= 64 && facts.prefix[0] == 'M' && facts.prefix[1] == 'Z' {
			p := facts.prefix
			offset := int64(uint32(p[60]) | uint32(p[61])<<8 | uint32(p[62])<<16 | uint32(p[63])<<24)
			if offset <= facts.size-4 {
				var signature [4]byte
				if _, err := reader.ReadAt(signature[:], offset); err != nil {
					return nil, err
				}
				a.IsPEExecutable = bytes.Equal(signature[:], []byte{'P', 'E', 0, 0})
			}
		}
	}
	if cfg.ComputeEntropy {
		for _, count := range facts.counts {
			if count > 0 {
				p := float64(count) / float64(facts.size)
				a.Entropy -= p * math.Log2(p)
			}
		}
	}
	if cfg.DetectEmbeddedScripts {
		a.HasEmbeddedScript = facts.embedded
	}
	a.IsPasswordProtected = isPasswordProtected(facts.prefix)
	if bytes.HasPrefix(facts.prefix, []byte{0xd0, 0xcf, 0x11, 0xe0}) {
		a.IsPasswordProtected = a.IsPasswordProtected || facts.tokens["EncryptedPackage"] || facts.tokens["StrongEncryptionDataSpace"]
	}
	return a, nil
}
