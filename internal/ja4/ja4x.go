/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * JA4X X.509 certificate fingerprinting is licensed under the FoxIO License 1.1
 * Reference: https://github.com/FoxIO-LLC/ja4
 */

package ja4

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
)

// CertificateFingerprintData contains the data needed to compute a JA4X fingerprint
type CertificateFingerprintData struct {
	IssuerRDNs    []string // Issuer RDN OIDs as hex strings
	SubjectRDNs   []string // Subject RDN OIDs as hex strings
	ExtensionOIDs []string // Extension OIDs as hex strings
}

// ComputeJA4X computes the JA4X fingerprint for an X.509 certificate
// Format: {issuer_hash}_{subject_hash}_{extensions_hash}
// Each part is a 12-character truncated SHA256 hash
func ComputeJA4X(data *CertificateFingerprintData) string {
	issuerStr := strings.Join(data.IssuerRDNs, ",")
	subjectStr := strings.Join(data.SubjectRDNs, ",")
	extensionsStr := strings.Join(data.ExtensionOIDs, ",")

	return truncatedSHA256(issuerStr) + "_" +
		truncatedSHA256(subjectStr) + "_" +
		truncatedSHA256(extensionsStr)
}

// ComputeJA4XRaw returns the raw (unhashed) JA4X fingerprint
func ComputeJA4XRaw(data *CertificateFingerprintData) string {
	issuerStr := strings.Join(data.IssuerRDNs, ",")
	subjectStr := strings.Join(data.SubjectRDNs, ",")
	extensionsStr := strings.Join(data.ExtensionOIDs, ",")

	return issuerStr + "_" + subjectStr + "_" + extensionsStr
}

// ComputeJA4XFromCert computes the JA4X fingerprint directly from an x509.Certificate
func ComputeJA4XFromCert(cert *x509.Certificate) string {
	data := ExtractCertificateData(cert)
	return ComputeJA4X(data)
}

// ExtractCertificateData extracts JA4X-relevant data from an x509.Certificate
func ExtractCertificateData(cert *x509.Certificate) *CertificateFingerprintData {
	return &CertificateFingerprintData{
		IssuerRDNs:    extractRDNOIDs(cert.Issuer),
		SubjectRDNs:   extractRDNOIDs(cert.Subject),
		ExtensionOIDs: extractExtensionOIDs(cert),
	}
}

// ExtractCertificateDataFromDER extracts JA4X-relevant data from DER-encoded certificate
func ExtractCertificateDataFromDER(der []byte) (*CertificateFingerprintData, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return ExtractCertificateData(cert), nil
}

// extractRDNOIDs extracts OIDs from a pkix.Name as hex strings
func extractRDNOIDs(name pkix.Name) []string {
	var oids []string

	// The Names field contains all the RDNs in order
	for _, rdn := range name.Names {
		oidBytes, err := asn1.Marshal(rdn.Type)
		if err != nil {
			continue
		}
		// Skip the first 2 bytes (ASN.1 tag and length) to get just the OID bytes
		if len(oidBytes) > 2 {
			oids = append(oids, hex.EncodeToString(oidBytes[2:]))
		}
	}

	return oids
}

// extractExtensionOIDs extracts extension OIDs from a certificate as hex strings
func extractExtensionOIDs(cert *x509.Certificate) []string {
	var oids []string

	for _, ext := range cert.Extensions {
		oidBytes, err := asn1.Marshal(ext.Id)
		if err != nil {
			continue
		}
		// Skip the first 2 bytes (ASN.1 tag and length) to get just the OID bytes
		if len(oidBytes) > 2 {
			oids = append(oids, hex.EncodeToString(oidBytes[2:]))
		}
	}

	return oids
}

// ValidateJA4X checks if a JA4X fingerprint has the correct format
func ValidateJA4X(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return false
	}
	// Each part should be 12 hex characters
	for _, part := range parts {
		if len(part) != 12 {
			return false
		}
	}
	return true
}

// Common X.509 OID hex representations for reference
var CommonOIDs = map[string]string{
	"550403": "commonName",
	"550406": "countryName",
	"550407": "localityName",
	"550408": "stateOrProvinceName",
	"55040a": "organizationName",
	"55040b": "organizationalUnitName",
	"551d0e": "subjectKeyIdentifier",
	"551d0f": "keyUsage",
	"551d11": "subjectAltName",
	"551d13": "basicConstraints",
	"551d1f": "cRLDistributionPoints",
	"551d20": "certificatePolicies",
	"551d23": "authorityKeyIdentifier",
	"551d25": "extKeyUsage",
	"2b0601050507010e": "authorityInfoAccess",
}

// IsSelfSignedByJA4X checks if a certificate is likely self-signed based on JA4X
// A self-signed certificate has matching issuer and subject hashes
func IsSelfSignedByJA4X(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		return false
	}
	return parts[0] == parts[1]
}

