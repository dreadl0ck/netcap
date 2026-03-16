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

package tls_test

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/stream/tls"
	"github.com/dreadl0ck/netcap/types"
)

// Note: Full PCAP-based integration tests should be placed in
// the collector package tests to avoid import cycles.
// This file contains unit tests for the deduplication logic only.

// TestTLSCertificateDeduplication tests that duplicate certificates are properly deduplicated
func TestTLSCertificateDeduplication(t *testing.T) {
	// Reset certificate cache
	tls.ResetCertificates()

	// Create a mock certificate for testing deduplication
	mockCert := createMockCertificate("test-fingerprint-1", "example.com", "Example CA")

	// Add certificate first time
	isNew := tls.AddOrUpdateCertificate(mockCert)
	if !isNew {
		t.Error("First addition should return true (new certificate)")
	}

	size := tls.GetCertificateCount()
	if size != 1 {
		t.Errorf("Expected 1 certificate in cache, got %d", size)
	}

	// Add same certificate again (same fingerprint)
	mockCert2 := createMockCertificate("test-fingerprint-1", "example.com", "Example CA")
	mockCert2.Timestamp = mockCert.Timestamp + 1000000000 // 1 second later

	isNew = tls.AddOrUpdateCertificate(mockCert2)
	if isNew {
		t.Error("Second addition should return false (existing certificate)")
	}

	size = tls.GetCertificateCount()
	if size != 1 {
		t.Errorf("Expected 1 certificate in cache after duplicate, got %d", size)
	}

	// Add different certificate
	mockCert3 := createMockCertificate("test-fingerprint-2", "another.com", "Another CA")
	isNew = tls.AddOrUpdateCertificate(mockCert3)
	if !isNew {
		t.Error("Third addition (different cert) should return true (new certificate)")
	}

	size = tls.GetCertificateCount()
	if size != 2 {
		t.Errorf("Expected 2 certificates in cache, got %d", size)
	}
}

// TestCertificateCacheReset tests the ResetCertificates function
func TestCertificateCacheReset(t *testing.T) {
	// Reset cache before test to ensure clean state
	tls.ResetCertificates()

	// Add some certificates
	for i := range 5 {
		mockCert := createMockCertificate(
			string(rune('A'+i))+"-fingerprint",
			string(rune('a'+i))+"-example.com",
			"Test CA",
		)
		tls.AddOrUpdateCertificate(mockCert)
	}

	size := tls.GetCertificateCount()
	if size != 5 {
		t.Errorf("Expected 5 certificates before reset, got %d", size)
	}

	// Reset cache
	tls.ResetCertificates()

	size = tls.GetCertificateCount()
	if size != 0 {
		t.Errorf("Expected 0 certificates after reset, got %d", size)
	}
}

// TestCertificateMetadataTracking tests that FirstSeen, LastSeen, and SeenCount are properly tracked
func TestCertificateMetadataTracking(t *testing.T) {
	tls.ResetCertificates()

	baseTime := time.Now().UnixNano()
	mockCert := createMockCertificate("tracking-test", "tracking.example.com", "Tracking CA")
	mockCert.Timestamp = baseTime

	// First addition
	tls.AddOrUpdateCertificate(mockCert)

	// Verify initial metadata
	cert := tls.GetCertificate("tracking-test")
	if cert == nil {
		t.Fatal("Certificate not found after addition")
	}
	if cert.FirstSeen != baseTime {
		t.Errorf("FirstSeen should be %d, got %d", baseTime, cert.FirstSeen)
	}
	if cert.LastSeen != baseTime {
		t.Errorf("LastSeen should be %d, got %d", baseTime, cert.LastSeen)
	}
	if cert.SeenCount != 1 {
		t.Errorf("SeenCount should be 1, got %d", cert.SeenCount)
	}

	// Update with later timestamp
	mockCert2 := createMockCertificate("tracking-test", "tracking.example.com", "Tracking CA")
	mockCert2.Timestamp = baseTime + 5000000000 // 5 seconds later

	tls.AddOrUpdateCertificate(mockCert2)

	// Verify updated metadata
	cert = tls.GetCertificate("tracking-test")
	if cert == nil {
		t.Fatal("Certificate not found after update")
	}
	if cert.FirstSeen != baseTime {
		t.Errorf("FirstSeen should remain %d, got %d", baseTime, cert.FirstSeen)
	}
	if cert.LastSeen != baseTime+5000000000 {
		t.Errorf("LastSeen should be %d, got %d", baseTime+5000000000, cert.LastSeen)
	}
	if cert.SeenCount != 2 {
		t.Errorf("SeenCount should be 2, got %d", cert.SeenCount)
	}
}

// Helper function to create mock certificates for testing
func createMockCertificate(fingerprint, subject, issuer string) *types.TLSCertificate {
	now := time.Now()
	return &types.TLSCertificate{
		Timestamp:           now.UnixNano(),
		SrcIP:               "192.168.1.1",
		DstIP:               "192.168.1.2",
		SrcPort:             443,
		DstPort:             54321,
		ChainIndex:          0,
		SubjectCommonName:   subject,
		SubjectAltNames:     []string{subject, "www." + subject},
		SubjectOrganization: "Test Organization",
		SubjectCountry:      "US",
		IssuerCommonName:    issuer,
		IssuerOrganization:  "Test CA Organization",
		IssuerCountry:       "US",
		NotBefore:           now.Add(-365 * 24 * time.Hour).UnixNano(),
		NotAfter:            now.Add(365 * 24 * time.Hour).UnixNano(),
		IsExpired:           false,
		IsSelfSigned:        subject == issuer,
		DaysUntilExpiration: 365,
		SignatureAlgorithm:  "SHA256-RSA",
		PublicKeyAlgorithm:  "RSA",
		PublicKeySize:       2048,
		SerialNumber:        "0123456789ABCDEF",
		Version:             3,
		SHA256Fingerprint:   fingerprint,
		SHA1Fingerprint:     fingerprint + "-sha1", // Mock SHA1 fingerprint
		KeyUsage:            []string{"DigitalSignature", "KeyEncipherment"},
		ExtKeyUsage:         []string{"ServerAuth"},
		IsCA:                false,
		MaxPathLen:          -1,
	}
}
