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

package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdio "io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// CertificateSummary represents aggregated information for a single TLS certificate
type CertificateSummary struct {
	Timestamp           int64    `json:"timestamp"`
	SrcIP               string   `json:"srcIP"`
	SrcPort             int32    `json:"srcPort"`
	DstIP               string   `json:"dstIP"`
	DstPort             int32    `json:"dstPort"`
	SrcMAC              string   `json:"srcMAC"`
	DstMAC              string   `json:"dstMAC"`
	ChainIndex          int32    `json:"chainIndex"`
	SubjectCommonName   string   `json:"subjectCommonName"`
	SubjectAltNames     []string `json:"subjectAltNames"`
	SubjectOrganization string   `json:"subjectOrganization"`
	SubjectCountry      string   `json:"subjectCountry"`
	SubjectLocality     string   `json:"subjectLocality"`
	SubjectProvince     string   `json:"subjectProvince"`
	IssuerCommonName    string   `json:"issuerCommonName"`
	IssuerOrganization  string   `json:"issuerOrganization"`
	IssuerCountry       string   `json:"issuerCountry"`
	NotBefore           int64    `json:"notBefore"`
	NotAfter            int64    `json:"notAfter"`
	IsExpired           bool     `json:"isExpired"`
	IsSelfSigned        bool     `json:"isSelfSigned"`
	DaysUntilExpiration int64    `json:"daysUntilExpiration"`
	IsNotYetValid       bool     `json:"isNotYetValid"`
	HasWeakSignature    bool     `json:"hasWeakSignature"`
	HasShortKeySize     bool     `json:"hasShortKeySize"`
	SignatureAlgorithm  string   `json:"signatureAlgorithm"`
	PublicKeyAlgorithm  string   `json:"publicKeyAlgorithm"`
	PublicKeySize       int32    `json:"publicKeySize"`
	SerialNumber        string   `json:"serialNumber"`
	Version             int32    `json:"version"`
	SHA256Fingerprint   string   `json:"sha256Fingerprint"`
	SHA1Fingerprint     string   `json:"sha1Fingerprint"`
	KeyUsage            []string `json:"keyUsage"`
	ExtKeyUsage         []string `json:"extKeyUsage"`
	IsCA                bool     `json:"isCA"`
	MaxPathLen          int32    `json:"maxPathLen"`
	FirstSeen           int64    `json:"firstSeen"`
	LastSeen            int64    `json:"lastSeen"`
	SeenCount           int64    `json:"seenCount"`
	// JA4X certificate fingerprinting
	Ja4x            string `json:"ja4x"`
	Ja4xRaw         string `json:"ja4xRaw"`
	Ja4xDescription string `json:"ja4xDescription"`
	// Community ID for cross-tool correlation
	CommunityID string `json:"communityId"`
}

// CertificatesResponse contains the list of certificates
type CertificatesResponse struct {
	Certificates []CertificateSummary `json:"certificates"`
	TotalCount   int                  `json:"totalCount"`
}

// handleCertificates returns a list of all TLS certificates
func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	certificates, err := readCertificates(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read certificates: %v", err)
		http.Error(w, "Failed to read certificates", http.StatusInternalServerError)
		return
	}

	response := CertificatesResponse{
		Certificates: certificates,
		TotalCount:   len(certificates),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readCertificates reads and aggregates TLSCertificate data from the output directory
func readCertificates(outDir string) ([]CertificateSummary, error) {
	filePath := filepath.Join(outDir, "TLSCertificate.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] TLSCertificate file not found: %s", filePath)
		return []CertificateSummary{}, nil
	}

	// Read TLSCertificate records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, err
	}

	// Use a map to deduplicate certificates by SHA256 fingerprint
	certMap := make(map[string]*CertificateSummary)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading TLSCertificate record: %v", err)
			continue
		}

		// Type assert to TLSCertificate
		cert, ok := record.(*types.TLSCertificate)
		if !ok {
			continue
		}

		// Use SHA256 fingerprint as unique key for deduplication
		key := cert.SHA256Fingerprint
		if key == "" {
			// Fallback to serial number + issuer if no fingerprint
			key = cert.SerialNumber + "|" + cert.IssuerCommonName
		}

		if existing, found := certMap[key]; found {
			// Update existing certificate with aggregated data
			existing.SeenCount++
			if cert.Timestamp < existing.FirstSeen || existing.FirstSeen == 0 {
				existing.FirstSeen = cert.Timestamp
			}
			if cert.Timestamp > existing.LastSeen {
				existing.LastSeen = cert.Timestamp
			}
		} else {
			// Add new certificate
			certMap[key] = &CertificateSummary{
				Timestamp:           cert.Timestamp,
				SrcIP:               cert.SrcIP,
				SrcPort:             cert.SrcPort,
				DstIP:               cert.DstIP,
				DstPort:             cert.DstPort,
				SrcMAC:              cert.SrcMAC,
				DstMAC:              cert.DstMAC,
				ChainIndex:          cert.ChainIndex,
				SubjectCommonName:   cert.SubjectCommonName,
				SubjectAltNames:     cert.SubjectAltNames,
				SubjectOrganization: cert.SubjectOrganization,
				SubjectCountry:      cert.SubjectCountry,
				SubjectLocality:     cert.SubjectLocality,
				SubjectProvince:     cert.SubjectProvince,
				IssuerCommonName:    cert.IssuerCommonName,
				IssuerOrganization:  cert.IssuerOrganization,
				IssuerCountry:       cert.IssuerCountry,
				NotBefore:           cert.NotBefore,
				NotAfter:            cert.NotAfter,
				IsExpired:           cert.IsExpired,
				IsSelfSigned:        cert.IsSelfSigned,
				DaysUntilExpiration: cert.DaysUntilExpiration,
				IsNotYetValid:       cert.IsNotYetValid,
				HasWeakSignature:    cert.HasWeakSignature,
				HasShortKeySize:     cert.HasShortKeySize,
				SignatureAlgorithm:  cert.SignatureAlgorithm,
				PublicKeyAlgorithm:  cert.PublicKeyAlgorithm,
				PublicKeySize:       cert.PublicKeySize,
				SerialNumber:        cert.SerialNumber,
				Version:             cert.Version,
				SHA256Fingerprint:   cert.SHA256Fingerprint,
				SHA1Fingerprint:     cert.SHA1Fingerprint,
				KeyUsage:            cert.KeyUsage,
				ExtKeyUsage:         cert.ExtKeyUsage,
				IsCA:                cert.IsCA,
				MaxPathLen:          cert.MaxPathLen,
				FirstSeen:           cert.Timestamp,
				LastSeen:            cert.Timestamp,
				SeenCount:           1,
				// JA4X certificate fingerprinting
				Ja4x:            cert.Ja4X,
				Ja4xRaw:         cert.Ja4XRaw,
				Ja4xDescription: cert.Ja4XDescription,
				// Community ID for cross-tool correlation
				CommunityID: cert.CommunityID,
			}
		}
	}

	// Convert map to slice
	certificates := make([]CertificateSummary, 0, len(certMap))
	for _, cert := range certMap {
		certificates = append(certificates, *cert)
	}

	// Sort by seen count descending
	sort.Slice(certificates, func(i, j int) bool {
		return certificates[i].SeenCount > certificates[j].SeenCount
	})

	return certificates, nil
}

// handleCertificateDownloadPCAP filters and downloads PCAP for a specific certificate's connection
func (s *Server) handleCertificateDownloadPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	srcIP := r.URL.Query().Get("srcIP")
	srcPort := r.URL.Query().Get("srcPort")
	dstIP := r.URL.Query().Get("dstIP")
	dstPort := r.URL.Query().Get("dstPort")

	if srcIP == "" || srcPort == "" || dstIP == "" || dstPort == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	activeInputFile := s.activeInputFile

	// In service mode, use the current session's input file
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			activeInputFile = session.InputFile
		}
	}
	s.mu.RUnlock()

	if activeInputFile == "" {
		http.Error(w, "No active input file", http.StatusServiceUnavailable)
		return
	}

	// Check if input file exists
	if _, err := os.Stat(activeInputFile); os.IsNotExist(err) {
		http.Error(w, "Input file not found", http.StatusNotFound)
		return
	}

	// Create BPF filter for the connection (TLS is typically on TCP)
	bpf := fmt.Sprintf("(host %s and port %s) and (host %s and port %s) and tcp",
		srcIP, srcPort, dstIP, dstPort)

	// Create temporary output file
	tempDir := os.TempDir()
	outputFile := filepath.Join(tempDir, fmt.Sprintf("certificate_%s-%s_%s-%s.pcap",
		strings.ReplaceAll(srcIP, ".", "_"),
		srcPort,
		strings.ReplaceAll(dstIP, ".", "_"),
		dstPort))

	// Use tcpdump to filter the PCAP with a timeout
	tcpdumpCmd := "tcpdump"
	args := []string{"-r", activeInputFile, "-w", outputFile, bpf}

	log.Printf("[WebUI] Filtering PCAP for certificate: %s %v", tcpdumpCmd, args)

	// Create context with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, tcpdumpCmd, args...)
	output, err := cmd.CombinedOutput()

	log.Printf("[WebUI] tcpdump completed, err=%v, output=%s", err, string(output))

	if err != nil {
		log.Printf("[WebUI] tcpdump error: %v, output: %s", err, string(output))

		// Check for timeout
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "PCAP filtering timed out. The file may be too large or the filter too complex.", http.StatusRequestTimeout)
			return
		}

		// Check if tcpdump is not found
		if strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "not found") {
			http.Error(w, "tcpdump is not installed or not available in PATH. Please install tcpdump to use this feature.", http.StatusServiceUnavailable)
			return
		}

		// Check for permission errors
		if strings.Contains(string(output), "permission denied") || strings.Contains(string(output), "Operation not permitted") {
			http.Error(w, "Permission denied: tcpdump requires special capabilities. Please ensure the container has CAP_NET_RAW and CAP_NET_ADMIN capabilities.", http.StatusForbidden)
			return
		}

		http.Error(w, fmt.Sprintf("Failed to filter PCAP: %v - Output: %s", err, string(output)), http.StatusInternalServerError)
		return
	}

	// Check if output file was created
	fileInfo, err := os.Stat(outputFile)
	if err != nil {
		log.Printf("[WebUI] Output file not found: %v", err)
		http.Error(w, "Failed to create filtered PCAP", http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] Filtered PCAP created: %s, size: %d bytes", outputFile, fileInfo.Size())

	// Check if file is empty (no packets matched)
	if fileInfo.Size() == 0 {
		log.Printf("[WebUI] No packets matched filter, removing empty file")
		os.Remove(outputFile)
		http.Error(w, "No packets found for this certificate's connection", http.StatusNotFound)
		return
	}

	// PCAP files need at least 24 bytes for the header
	if fileInfo.Size() < 24 {
		log.Printf("[WebUI] File too small to be a valid PCAP (size: %d bytes)", fileInfo.Size())
		os.Remove(outputFile)
		http.Error(w, "Generated PCAP file is invalid", http.StatusInternalServerError)
		return
	}

	// Open the filtered PCAP file
	file, err := os.Open(outputFile)
	if err != nil {
		log.Printf("[WebUI] Failed to open filtered PCAP: %v", err)
		os.Remove(outputFile)
		http.Error(w, "Failed to read filtered PCAP", http.StatusInternalServerError)
		return
	}

	// Read entire file into memory
	fileData, err := stdio.ReadAll(file)
	file.Close()

	if err != nil {
		log.Printf("[WebUI] Failed to read PCAP file: %v", err)
		os.Remove(outputFile)
		http.Error(w, "Failed to read filtered PCAP", http.StatusInternalServerError)
		return
	}

	// Clean up temp file
	os.Remove(outputFile)

	// Verify we read the expected amount
	if len(fileData) != int(fileInfo.Size()) {
		log.Printf("[WebUI] File size mismatch: expected %d, read %d", fileInfo.Size(), len(fileData))
		http.Error(w, "File read error", http.StatusInternalServerError)
		return
	}

	log.Printf("[WebUI] Read PCAP file successfully: %d bytes", len(fileData))

	// Set headers for download
	filename := fmt.Sprintf("certificate_%s-%s_%s-%s.pcap", srcIP, srcPort, dstIP, dstPort)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
	w.Header().Set("Cache-Control", "no-cache")

	// Write the entire file
	bytesWritten, err := w.Write(fileData)
	if err != nil {
		log.Printf("[WebUI] Failed to send PCAP file after %d bytes: %v", bytesWritten, err)
		return
	}

	log.Printf("[WebUI] Successfully sent PCAP file: %d bytes written", bytesWritten)
}
