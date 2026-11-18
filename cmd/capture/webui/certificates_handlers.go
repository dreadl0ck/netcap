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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// CertificateSummary represents aggregated information for a single TLS certificate
type CertificateSummary struct {
	AssessmentTime      string   `json:"assessmentTimeNs"`
	AssessmentBasis     string   `json:"assessmentBasis"`
	ValidityState       string   `json:"validityState"`
	SelfSignatureState  string   `json:"selfSignatureState"`
	CertificateSender   string   `json:"certificateSender"`
	NotBeforeRFC3339    string   `json:"notBeforeRFC3339"`
	NotAfterRFC3339     string   `json:"notAfterRFC3339"`
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
	CommunityID  string   `json:"communityId"`
	CommunityIDs []string `json:"communityIds"`
}

// CertificatesResponse contains the list of certificates
type CertificatesResponse struct {
	Certificates []CertificateSummary `json:"certificates"`
	TotalCount   int                  `json:"totalCount"`
}

var certificateInventorySlots = make(chan struct{}, 2)

// handleCertificates returns a list of all TLS certificates
func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	var rows []CertificateSummary
	var err error
	if r.URL.Query().Get("mcpPage") == "true" {
		if r.Context().Err() != nil {
			return
		}
		select {
		case certificateInventorySlots <- struct{}{}:
			defer func() { <-certificateInventorySlots }()
		default:
			RespondJSON(w, http.StatusTooManyRequests, map[string]string{"error": "certificate inventory is busy"})
			return
		}
		budget := &inventoryAuditBudget{ctx: r.Context(), stored: maxCollectionPageScanBytes, bodies: maxCollectionPageScanBytes, rows: maxCollectionPageRows}
		rows, err = readCertificateInventory(outDir, budget)
	} else {
		var snapshot *certificateSnapshot
		snapshot, err = certificateSnapshotFor(outDir)
		if err == nil {
			rows = snapshot.rows
		}
	}
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		if errors.Is(err, errInventoryAuditLimit) {
			RespondJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[WebUI] Failed to read certificates: %v", err)
		http.Error(w, "Failed to read certificates", http.StatusInternalServerError)
		return
	}

	response := CertificatesResponse{
		Certificates: rows,
		TotalCount:   len(rows),
	}

	w.Header().Set("Content-Type", "application/json")
	if respondCollectionPage(w, r, response.Certificates, "certificates") {
		return
	}
	json.NewEncoder(w).Encode(response)
}

// readCertificates reads and aggregates TLSCertificate data from the output directory
func readCertificates(outDir string) ([]CertificateSummary, error) {
	return readCertificateInventory(outDir, nil)
}

func readCertificateInventory(outDir string, budget *inventoryAuditBudget) ([]CertificateSummary, error) {
	reader, err := budget.open(filepath.Join(outDir, "TLSCertificate.ncap.gz"), types.Type_NC_TLSCertificate)
	if errors.Is(err, os.ErrNotExist) {
		return []CertificateSummary{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Use a map to deduplicate certificates by SHA256 fingerprint
	certMap := make(map[string]*CertificateSummary)
	communityIDs := make(map[string]map[string]struct{})

	// Read all records
	for {
		raw, err := budget.nextRaw(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		record, err := reader.DecodeRecord(raw)
		if err != nil {
			if budget != nil {
				return nil, err
			}
			log.Printf("[WebUI] Error decoding TLSCertificate record: %v", err)
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
		if cert.AssessmentBasis != "" {
			key += fmt.Sprintf("|%s|%s|%s|%s", cert.AssessmentBasis, cert.ValidityState, cert.SelfSignatureState, cert.CertificateSender)
		}
		if cert.CommunityID != "" {
			if communityIDs[key] == nil {
				communityIDs[key] = make(map[string]struct{})
			}
			communityIDs[key][cert.CommunityID] = struct{}{}
		}

		if existing, found := certMap[key]; found {
			// Update existing certificate with aggregated data
			existing.SeenCount++
			if cert.Timestamp < existing.FirstSeen || existing.FirstSeen == 0 {
				existing.FirstSeen = cert.Timestamp
				existing.Timestamp = cert.Timestamp
				existing.AssessmentTime = fmt.Sprint(cert.AssessmentTime)
				existing.DaysUntilExpiration = cert.DaysUntilExpiration
				existing.SrcIP, existing.DstIP = cert.SrcIP, cert.DstIP
				existing.SrcPort, existing.DstPort = cert.SrcPort, cert.DstPort
			}
			if cert.Timestamp > existing.LastSeen {
				existing.LastSeen = cert.Timestamp
			}
		} else {
			// Add new certificate
			certMap[key] = &CertificateSummary{
				AssessmentTime: fmt.Sprint(cert.AssessmentTime),
				AssessmentBasis: func() string {
					if cert.AssessmentBasis == "" {
						return "legacy-unqualified"
					}
					return cert.AssessmentBasis
				}(),
				ValidityState: func() string {
					if cert.ValidityState == "" {
						return "legacy-unqualified"
					}
					return cert.ValidityState
				}(),
				SelfSignatureState: func() string {
					if cert.SelfSignatureState == "" {
						return "legacy-unqualified"
					}
					return cert.SelfSignatureState
				}(),
				CertificateSender: func() string {
					if cert.CertificateSender == "" {
						return "unknown"
					}
					return cert.CertificateSender
				}(),
				NotBeforeRFC3339:    cert.NotBeforeRFC3339,
				NotAfterRFC3339:     cert.NotAfterRFC3339,
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
	keys := make([]string, 0, len(certMap))
	for key := range certMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if certMap[a].SeenCount != certMap[b].SeenCount {
			return certMap[a].SeenCount > certMap[b].SeenCount
		}
		return a < b
	})
	for _, key := range keys {
		cert := certMap[key]
		for id := range communityIDs[key] {
			cert.CommunityIDs = append(cert.CommunityIDs, id)
		}
		sort.Strings(cert.CommunityIDs)
		certificates = append(certificates, *cert)
	}

	return certificates, nil
}

// handleCertificateDownloadPCAP filters and downloads PCAP for a specific certificate's connection
func (s *Server) handleCertificateDownloadPCAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	selection, err := parseTCPPacketSelection(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	srcIP, srcPort := query.Get("srcIP"), query.Get("srcPort")
	dstIP, dstPort := query.Get("dstIP"), query.Get("dstPort")

	activeInputFile, _ := s.resolveInputFileFromRequest(r)

	if activeInputFile == "" {
		http.Error(w, "No active input file", http.StatusServiceUnavailable)
		return
	}

	// Check if input file exists
	if _, err := os.Stat(activeInputFile); os.IsNotExist(err) {
		http.Error(w, "Input file not found", http.StatusNotFound)
		return
	}

	release := admitPacketDownload(w)
	if release == nil {
		return
	}
	defer release()
	temp, err := os.CreateTemp("", "netcap-certificate-*.pcap")
	if err != nil {
		http.Error(w, "Failed to create certificate packet export", http.StatusInternalServerError)
		return
	}
	outputFile := temp.Name()
	defer os.Remove(outputFile)
	if err := temp.Close(); err != nil {
		http.Error(w, "Failed to close certificate packet export", http.StatusInternalServerError)
		return
	}

	// Filter the PCAP entirely in-process (no external tcpdump).
	log.Printf("[WebUI] Filtering PCAP for certificate in-process: %s -> %s (bpf: %s)", activeInputFile, outputFile, selection.bpf)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	written, err := filterPacketDownload(ctx, r, activeInputFile, selection.bpf, outputFile, selection.contains)
	if err != nil {
		log.Printf("[WebUI] PCAP filter error: %v", err)
		os.Remove(outputFile)
		if writePacketDownloadLimitError(w, err) {
			return
		}
		if isPCAPFilterTimeout(err) {
			http.Error(w, "PCAP filtering timed out. The file may be too large or the filter too complex.", http.StatusRequestTimeout)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to filter PCAP: %v", err), http.StatusInternalServerError)
		return
	}

	// No packets matched the filter.
	if written == 0 {
		log.Printf("[WebUI] No packets matched filter, removing empty file")
		os.Remove(outputFile)
		http.Error(w, "No packets found for this certificate's connection", http.StatusNotFound)
		return
	}

	writeClassicPacketDownload(w, outputFile, fmt.Sprintf("certificate_%s-%s_%s-%s.pcap", srcIP, srcPort, dstIP, dstPort))
}

// CountUniqueCertificates counts deduplicated certificates by SHA256 fingerprint.
// This matches the deduplication logic used by readCertificates / the certificates table.
func CountUniqueCertificates(outDir string) int64 {
	certs, err := certificateSnapshotFor(outDir)
	if err != nil {
		return 0
	}
	return int64(len(certs.rows))
}

// CountUniqueCertificatesWithCommunityIDFilter counts deduplicated certificates
// that match any of the given community IDs.
func CountUniqueCertificatesWithCommunityIDFilter(outDir string, communityIDs map[string]bool) int64 {
	if len(communityIDs) == 0 {
		return CountUniqueCertificates(outDir)
	}

	certs, err := certificateSnapshotFor(outDir)
	if err != nil {
		return 0
	}

	return certs.count(communityIDs)
}
