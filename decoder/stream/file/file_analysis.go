/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package file

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/entropy"
)

// FileAnalysis contains security analysis results for a file
type FileAnalysis struct {
	Entropy             float64
	MagicBytes          []byte
	TrueFileType        string
	TypeMismatch        bool
	IsPEExecutable      bool
	IsELFExecutable     bool
	IsMachO             bool
	HasEmbeddedScript   bool
	IsPasswordProtected bool
	YaraMatches         []string
	IsKnownMalware      bool
	ThreatName          string
}

// Magic byte signatures for common file types
var magicSignatures = map[string][]byte{
	// Executables
	"application/x-executable-pe":   {0x4D, 0x5A},             // PE (MZ header)
	"application/x-executable-elf":  {0x7F, 0x45, 0x4C, 0x46}, // ELF
	"application/x-mach-binary":     {0xCF, 0xFA, 0xED, 0xFE}, // Mach-O (64-bit)
	"application/x-mach-binary-32":  {0xCE, 0xFA, 0xED, 0xFE}, // Mach-O (32-bit)
	"application/x-mach-binary-fat": {0xCA, 0xFE, 0xBA, 0xBE}, // Mach-O (fat binary)

	// Archives
	"application/zip":              {0x50, 0x4B, 0x03, 0x04},             // ZIP
	"application/x-rar-compressed": {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, // RAR
	"application/gzip":             {0x1F, 0x8B},                         // GZIP
	"application/x-7z-compressed":  {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, // 7z
	"application/x-tar":            {0x75, 0x73, 0x74, 0x61, 0x72},       // TAR (at offset 257)

	// Documents
	"application/pdf":    {0x25, 0x50, 0x44, 0x46},                         // PDF
	"application/msword": {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, // OLE (DOC, XLS, PPT)

	// Images
	"image/jpeg": {0xFF, 0xD8, 0xFF},                               // JPEG
	"image/png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG
	"image/gif":  {0x47, 0x49, 0x46, 0x38},                         // GIF
	"image/bmp":  {0x42, 0x4D},                                     // BMP
	"image/webp": {0x52, 0x49, 0x46, 0x46},                         // WebP (RIFF header)

	// Scripts (text-based, detected by content)
	// "text/x-script" patterns are handled separately
}

// AnalyzeFile performs security analysis on file content
// Respects configuration settings for which analyses to perform
func AnalyzeFile(content []byte, filename string) *FileAnalysis {
	cfg := GetGlobalConfig()
	analysis := &FileAnalysis{}

	if len(content) == 0 {
		return analysis
	}

	// Extract magic bytes (first 8 bytes)
	magicLen := 8
	if len(content) < magicLen {
		magicLen = len(content)
	}
	analysis.MagicBytes = content[:magicLen]

	// Detect true file type from magic bytes
	analysis.TrueFileType = detectFileTypeFromMagic(content)

	// Check for type mismatch (extension vs magic bytes)
	if filename != "" {
		ext := strings.ToLower(filepath.Ext(filename))
		expectedType := extensionToMimeType(ext)
		if expectedType != "" && analysis.TrueFileType != "" &&
			!strings.HasPrefix(analysis.TrueFileType, expectedType) &&
			!strings.HasPrefix(expectedType, analysis.TrueFileType) {
			analysis.TypeMismatch = true
		}
	}

	// Detect executables (if enabled)
	if cfg.FileExtraction.Advanced.DetectExecutables {
		analysis.IsPEExecutable = isPEExecutable(content)
		analysis.IsELFExecutable = isELFExecutable(content)
		analysis.IsMachO = isMachOExecutable(content)
	}

	// Calculate entropy (if enabled)
	if cfg.FileExtraction.Advanced.ComputeEntropy {
		analysis.Entropy = calculateEntropy(content)
	}

	// Detect embedded scripts (if enabled)
	if cfg.FileExtraction.Advanced.DetectEmbeddedScripts {
		analysis.HasEmbeddedScript = hasEmbeddedScript(content)
	}

	// Check for password-protected archives
	analysis.IsPasswordProtected = isPasswordProtected(content)

	// YARA scanning
	if cfg.FileExtraction.Advanced.EnableYaraScanning && cfg.FileExtraction.Advanced.YaraRulesPath != "" {
		scanner := GetGlobalYaraScanner()
		if scanner != nil {
			matches, err := scanner.ScanBytes(content)
			if err == nil {
				analysis.YaraMatches = matches
			}
		}
	}

	return analysis
}

// calculateEntropy computes Shannon entropy of the data
// Returns a value between 0 (uniform) and 8 (random)
// Values > 7.0 typically indicate encrypted or compressed content
func calculateEntropy(data []byte) float64 {
	return entropy.Bytes(data)
}

// detectFileTypeFromMagic detects file type from magic bytes
func detectFileTypeFromMagic(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	for mimeType, magic := range magicSignatures {
		if len(data) >= len(magic) && bytes.HasPrefix(data, magic) {
			return mimeType
		}
	}

	// Check for text-based scripts
	if isTextFile(data) {
		scriptType := detectScriptType(data)
		if scriptType != "" {
			return scriptType
		}
		return "text/plain"
	}

	return "application/octet-stream"
}

// isPEExecutable checks if content is a Windows PE executable
func isPEExecutable(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	// Check MZ header
	if data[0] != 0x4D || data[1] != 0x5A {
		return false
	}

	// Get PE header offset from e_lfanew field at offset 0x3C
	if len(data) < 0x40 {
		return false
	}

	peOffset := int(data[0x3C]) | int(data[0x3D])<<8 | int(data[0x3E])<<16 | int(data[0x3F])<<24
	if peOffset < 0 || peOffset+4 > len(data) {
		return false
	}

	// Check PE signature "PE\0\0"
	return data[peOffset] == 0x50 && data[peOffset+1] == 0x45 &&
		data[peOffset+2] == 0x00 && data[peOffset+3] == 0x00
}

// isELFExecutable checks if content is a Linux ELF executable
func isELFExecutable(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46
}

// isMachOExecutable checks if content is a macOS Mach-O executable
func isMachOExecutable(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// 64-bit Mach-O
	if data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE {
		return true
	}
	// 32-bit Mach-O
	if data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE {
		return true
	}
	// Fat binary (universal)
	if data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE {
		return true
	}

	return false
}

// hasEmbeddedScript checks for embedded VBA, JavaScript, or PowerShell
func hasEmbeddedScript(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	dataStr := string(data)

	// VBA/Office macros indicators
	vbaIndicators := []string{
		"Sub Auto", // AutoOpen, AutoExec, etc.
		"Function ",
		"Attribute VB_",
		"CreateObject",
		"Shell(",
		"WScript.Shell",
		"Scripting.FileSystemObject",
	}

	// JavaScript indicators
	jsIndicators := []string{
		"eval(",
		"Function(",
		"document.write(",
		"ActiveXObject",
		"WScript.",
	}

	// PowerShell indicators
	psIndicators := []string{
		"powershell",
		"-enc ",
		"-EncodedCommand",
		"Invoke-Expression",
		"IEX(",
		"Invoke-WebRequest",
		"DownloadString",
		"DownloadFile",
		"FromBase64String",
		"[Convert]::",
		"[System.Text.Encoding]::",
	}

	dataLower := strings.ToLower(dataStr)

	for _, indicator := range vbaIndicators {
		if strings.Contains(dataStr, indicator) {
			return true
		}
	}

	for _, indicator := range jsIndicators {
		if strings.Contains(dataStr, indicator) {
			return true
		}
	}

	for _, indicator := range psIndicators {
		if strings.Contains(dataLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// isPasswordProtected checks if a file appears to be password-protected
func isPasswordProtected(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	// ZIP with encryption
	if bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) {
		// Check general purpose bit flag at offset 6
		if len(data) > 7 {
			generalPurpose := uint16(data[6]) | uint16(data[7])<<8
			if generalPurpose&0x01 != 0 { // Bit 0 = encrypted
				return true
			}
		}
	}

	// Office documents with encryption (OLE format)
	if bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0}) {
		// Simplified check - look for encryption markers in the file
		if bytes.Contains(data, []byte("EncryptedPackage")) ||
			bytes.Contains(data, []byte("StrongEncryptionDataSpace")) {
			return true
		}
	}

	return false
}

// isTextFile checks if content appears to be text
func isTextFile(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check first 512 bytes for non-printable characters
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}

	nonPrintable := 0
	for _, b := range data[:checkLen] {
		if b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F {
			nonPrintable++
		}
	}

	// Allow up to 5% non-printable characters
	return float64(nonPrintable)/float64(checkLen) < 0.05
}

// detectScriptType detects the type of script from content
func detectScriptType(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	content := string(data)

	// Check shebang
	if strings.HasPrefix(content, "#!") {
		firstLine := strings.Split(content, "\n")[0]
		if strings.Contains(firstLine, "python") {
			return "text/x-python"
		}
		if strings.Contains(firstLine, "bash") || strings.Contains(firstLine, "/sh") {
			return "text/x-shellscript"
		}
		if strings.Contains(firstLine, "perl") {
			return "text/x-perl"
		}
		if strings.Contains(firstLine, "ruby") {
			return "text/x-ruby"
		}
		if strings.Contains(firstLine, "node") {
			return "application/javascript"
		}
	}

	// Check for PowerShell
	if strings.Contains(content, "param(") || strings.Contains(content, "$PSVersionTable") ||
		strings.Contains(content, "function ") && strings.Contains(content, "cmdlet") {
		return "text/x-powershell"
	}

	// Check for JavaScript
	if strings.Contains(content, "function(") || strings.Contains(content, "var ") ||
		strings.Contains(content, "const ") || strings.Contains(content, "let ") {
		return "application/javascript"
	}

	// Check for VBScript
	if strings.Contains(content, "Sub ") || strings.Contains(content, "Function ") &&
		strings.Contains(content, "End Sub") {
		return "text/vbscript"
	}

	return ""
}

// extensionToMimeType maps file extensions to expected MIME types
func extensionToMimeType(ext string) string {
	mimeTypes := map[string]string{
		".exe":   "application/x-executable-pe",
		".dll":   "application/x-executable-pe",
		".so":    "application/x-executable-elf",
		".dylib": "application/x-mach-binary",
		".zip":   "application/zip",
		".rar":   "application/x-rar-compressed",
		".gz":    "application/gzip",
		".7z":    "application/x-7z-compressed",
		".tar":   "application/x-tar",
		".pdf":   "application/pdf",
		".doc":   "application/msword",
		".docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xls":   "application/vnd.ms-excel",
		".xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".jpg":   "image/jpeg",
		".jpeg":  "image/jpeg",
		".png":   "image/png",
		".gif":   "image/gif",
		".bmp":   "image/bmp",
		".webp":  "image/webp",
		".js":    "application/javascript",
		".ps1":   "text/x-powershell",
		".py":    "text/x-python",
		".sh":    "text/x-shellscript",
		".bat":   "text/x-batch",
		".cmd":   "text/x-batch",
		".vbs":   "text/vbscript",
	}

	return mimeTypes[ext]
}
