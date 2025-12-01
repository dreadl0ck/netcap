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

package tls

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/internal/ja4"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

/*
 * TLS - Transport Layer Security
 */

type tlsReader struct {
	conversation *core.ConversationInfo
}

// New returns a new TLS reader
func (h *tlsReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &tlsReader{
		conversation: conversation,
	}
}

// Decode parses the stream according to the TLS protocol
func (h *tlsReader) Decode() {
	tlsLog.Info("TLS Decode() called",
		zap.String("ident", h.conversation.Ident),
		zap.Int("dataFragments", len(h.conversation.Data)),
		zap.String("clientIP", h.conversation.ClientIP),
		zap.String("serverIP", h.conversation.ServerIP),
		zap.Int("clientPort", int(h.conversation.ClientPort)),
		zap.Int("serverPort", int(h.conversation.ServerPort)),
	)

	// Prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		tlsLog.Error("TLS Decoder.Writer is nil - cannot write TLS audit records!")
		return
	}

	// Reassemble the server data (where certificates are sent)
	var serverBuf bytes.Buffer
	for _, d := range h.conversation.Data {
		// Only process server-to-client data
		if d.Direction() == reassembly.TCPDirServerToClient {
			// Limit buffer size to avoid memory issues (certificates usually arrive early in handshake)
			if serverBuf.Len() < 64*1024 { // 64KB should be enough for most certificate chains
				serverBuf.Write(d.Raw())
			}
		}
	}

	tlsLog.Debug("Processing TLS handshake data",
		zap.Int("serverDataSize", serverBuf.Len()),
	)

	// Parse TLS records looking for Certificate handshake messages
	h.parseTLSRecords(serverBuf.Bytes())

	tlsLog.Info("TLS decode complete",
		zap.String("ident", h.conversation.Ident),
	)
}

// parseTLSRecords parses TLS records from the byte stream
func (h *tlsReader) parseTLSRecords(data []byte) {
	reader := bytes.NewReader(data)

	for {
		// Read TLS record header (5 bytes)
		var recordHeader [5]byte
		n, err := reader.Read(recordHeader[:])
		if err == io.EOF || n < 5 {
			break
		}
		if err != nil {
			tlsLog.Debug("Error reading TLS record header", zap.Error(err))
			break
		}

		contentType := recordHeader[0]
		// version := binary.BigEndian.Uint16(recordHeader[1:3])
		length := binary.BigEndian.Uint16(recordHeader[3:5])

		tlsLog.Debug("TLS record",
			zap.Uint8("contentType", contentType),
			zap.Uint16("length", length),
		)

		// Check if it's a handshake record
		if contentType != recordTypeHandshake {
			// Skip this record
			_, err = reader.Seek(int64(length), io.SeekCurrent)
			if err != nil {
				break
			}
			continue
		}

		// Read the handshake data
		handshakeData := make([]byte, length)
		n, err = reader.Read(handshakeData)
		if err != nil || n < int(length) {
			tlsLog.Debug("Error reading handshake data", zap.Error(err))
			break
		}

		// Parse handshake messages within this record
		h.parseHandshakeMessages(handshakeData)
	}
}

// parseHandshakeMessages parses handshake messages from the data
func (h *tlsReader) parseHandshakeMessages(data []byte) {
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		// Read handshake message header
		handshakeType := data[offset]
		msgLength := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		tlsLog.Debug("Handshake message",
			zap.Uint8("type", handshakeType),
			zap.Int("length", msgLength),
		)

		if offset+msgLength > len(data) {
			tlsLog.Debug("Handshake message length exceeds available data")
			break
		}

		msgData := data[offset : offset+msgLength]

		// Check if it's a Certificate message (0x0b)
		if handshakeType == handshakeTypeCertificate {
			tlsLog.Info("Found Certificate handshake message",
				zap.Int("length", msgLength),
			)
			h.parseCertificateMessage(msgData)
		}

		offset += msgLength
	}
}

// parseCertificateMessage parses a TLS Certificate handshake message
func (h *tlsReader) parseCertificateMessage(data []byte) {
	if len(data) < 3 {
		tlsLog.Debug("Certificate message too short")
		return
	}

	// Read total certificates length (3 bytes)
	certsLength := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	offset := 3

	tlsLog.Debug("Certificate message",
		zap.Int("certsLength", certsLength),
	)

	if offset+certsLength > len(data) {
		tlsLog.Debug("Certificates length exceeds available data")
		return
	}

	chainIndex := int32(0)

	// Parse each certificate in the chain
	for offset < len(data) {
		if offset+3 > len(data) {
			break
		}

		// Read certificate length (3 bytes)
		certLength := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLength > len(data) {
			tlsLog.Debug("Certificate length exceeds available data",
				zap.Int("certLength", certLength),
				zap.Int("available", len(data)-offset),
			)
			break
		}

		certData := data[offset : offset+certLength]
		offset += certLength

		tlsLog.Info("Parsing certificate",
			zap.Int("chainIndex", int(chainIndex)),
			zap.Int("certLength", certLength),
		)

		// Parse the X.509 certificate
		h.parseCertificate(certData, chainIndex)
		chainIndex++
	}

	tlsLog.Info("Parsed certificate chain",
		zap.Int32("totalCerts", chainIndex),
	)
}

// parseCertificate parses an X.509 certificate and creates a TLSCertificate audit record
func (h *tlsReader) parseCertificate(certData []byte, chainIndex int32) {
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		tlsLog.Error("Failed to parse X.509 certificate",
			zap.Error(err),
			zap.Int("dataLength", len(certData)),
		)
		return
	}

	// Calculate fingerprints
	sha256Hash := sha256.Sum256(certData)
	sha1Hash := sha1.Sum(certData)

	sha256Fingerprint := hex.EncodeToString(sha256Hash[:])
	sha1Fingerprint := hex.EncodeToString(sha1Hash[:])

	// Extract Subject information
	subjectCN := cert.Subject.CommonName
	subjectOrg := ""
	if len(cert.Subject.Organization) > 0 {
		subjectOrg = cert.Subject.Organization[0]
	}
	subjectCountry := ""
	if len(cert.Subject.Country) > 0 {
		subjectCountry = cert.Subject.Country[0]
	}
	subjectLocality := ""
	if len(cert.Subject.Locality) > 0 {
		subjectLocality = cert.Subject.Locality[0]
	}
	subjectProvince := ""
	if len(cert.Subject.Province) > 0 {
		subjectProvince = cert.Subject.Province[0]
	}

	// Extract Issuer information
	issuerCN := cert.Issuer.CommonName
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}
	issuerCountry := ""
	if len(cert.Issuer.Country) > 0 {
		issuerCountry = cert.Issuer.Country[0]
	}

	// Perform certificate validations
	now := time.Now()

	// Check if self-signed (Subject == Issuer)
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	// Check if expired (current time is after NotAfter)
	isExpired := now.After(cert.NotAfter)

	// Check if not yet valid (current time is before NotBefore)
	isNotYetValid := now.Before(cert.NotBefore)

	// Calculate days until expiration
	daysUntilExpiration := int64(cert.NotAfter.Sub(now).Hours() / 24)
	if isExpired {
		// If expired, show negative days (how long it's been expired)
		daysUntilExpiration = -int64(now.Sub(cert.NotAfter).Hours() / 24)
	}

	// Validate certificate for security issues
	hasWeakSignature := isWeakSignatureAlgorithm(cert.SignatureAlgorithm)
	hasShortKeySize := false

	// Get public key size for validation
	pubKeySize := getPublicKeySize(cert)
	if pubKeySize > 0 {
		hasShortKeySize = isShortKeySize(cert.PublicKeyAlgorithm, pubKeySize)
	}

	// Log validation results
	if isExpired {
		tlsLog.Warn("Certificate is expired",
			zap.String("subject", cert.Subject.CommonName),
			zap.Time("expiredSince", cert.NotAfter),
			zap.Int64("daysExpired", -daysUntilExpiration),
		)
	}

	if isNotYetValid {
		tlsLog.Warn("Certificate is not yet valid",
			zap.String("subject", cert.Subject.CommonName),
			zap.Time("validFrom", cert.NotBefore),
		)
	}

	if isSelfSigned {
		tlsLog.Info("Certificate is self-signed",
			zap.String("subject", cert.Subject.CommonName),
		)
	}

	if hasWeakSignature {
		tlsLog.Warn("Certificate uses weak signature algorithm",
			zap.String("subject", cert.Subject.CommonName),
			zap.String("algorithm", cert.SignatureAlgorithm.String()),
		)
	}

	if hasShortKeySize {
		tlsLog.Warn("Certificate uses short key size",
			zap.String("subject", cert.Subject.CommonName),
			zap.String("algorithm", cert.PublicKeyAlgorithm.String()),
			zap.Int32("keySize", pubKeySize),
		)
	}

	// Extract Key Usage
	keyUsage := extractKeyUsage(cert.KeyUsage)
	extKeyUsage := extractExtKeyUsage(cert.ExtKeyUsage)

	// Extract MaxPathLen for CA certificates
	maxPathLen := int32(-1)
	if cert.IsCA && cert.MaxPathLen > 0 {
		maxPathLen = int32(cert.MaxPathLen)
	} else if cert.IsCA && cert.MaxPathLenZero {
		maxPathLen = 0
	}

	// Compute JA4X fingerprint
	certFPData := ja4.ExtractCertificateData(cert)
	ja4xFingerprint := ja4.ComputeJA4X(certFPData)
	ja4xRaw := ja4.ComputeJA4XRaw(certFPData)

	// Lookup JA4X fingerprint in database for enrichment
	ja4xDescription := resolvers.LookupJA4X(ja4xFingerprint)

	tlsCert := &types.TLSCertificate{
		Timestamp:           h.conversation.FirstClientPacket.UnixNano(),
		SrcIP:               h.conversation.ServerIP, // Server sends the certificate
		DstIP:               h.conversation.ClientIP,
		SrcMAC:              "", // MACs not available at stream level
		DstMAC:              "",
		SrcPort:             h.conversation.ServerPort,
		DstPort:             h.conversation.ClientPort,
		ChainIndex:          chainIndex,
		SubjectCommonName:   subjectCN,
		SubjectAltNames:     cert.DNSNames,
		SubjectOrganization: subjectOrg,
		SubjectCountry:      subjectCountry,
		SubjectLocality:     subjectLocality,
		SubjectProvince:     subjectProvince,
		IssuerCommonName:    issuerCN,
		IssuerOrganization:  issuerOrg,
		IssuerCountry:       issuerCountry,
		NotBefore:           cert.NotBefore.UnixNano(),
		NotAfter:            cert.NotAfter.UnixNano(),
		IsExpired:           isExpired,
		IsSelfSigned:        isSelfSigned,
		DaysUntilExpiration: daysUntilExpiration,
		IsNotYetValid:       isNotYetValid,
		HasWeakSignature:    hasWeakSignature,
		HasShortKeySize:     hasShortKeySize,
		SignatureAlgorithm:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
		PublicKeySize:       pubKeySize,
		SerialNumber:        formatSerialNumber(cert.SerialNumber),
		Version:             int32(cert.Version),
		SHA256Fingerprint:   sha256Fingerprint,
		SHA1Fingerprint:     sha1Fingerprint,
		KeyUsage:            keyUsage,
		ExtKeyUsage:         extKeyUsage,
		IsCA:                cert.IsCA,
		MaxPathLen:          maxPathLen,
		RawCertificate:      certData, // Store raw certificate
		Ja4X:                ja4xFingerprint,
		Ja4XRaw:             ja4xRaw,
		Ja4XDescription:     ja4xDescription,
		CommunityID:         h.conversation.CommunityID, // Community ID for cross-tool correlation
	}

	tlsLog.Info("Parsed certificate successfully",
		zap.String("subject", subjectCN),
		zap.String("issuer", issuerCN),
		zap.String("sha256", sha256Fingerprint),
		zap.Bool("isCA", cert.IsCA),
		zap.Bool("isSelfSigned", isSelfSigned),
		zap.Bool("isExpired", isExpired),
		zap.Bool("isNotYetValid", isNotYetValid),
		zap.Bool("hasWeakSignature", hasWeakSignature),
		zap.Bool("hasShortKeySize", hasShortKeySize),
		zap.Int32("pubKeySize", pubKeySize),
	)

	// Add or update certificate in cache
	addOrUpdateCertificate(tlsCert)
}

// extractKeyUsage converts x509.KeyUsage bitmask to string array
func extractKeyUsage(usage x509.KeyUsage) []string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return usages
}

// extractExtKeyUsage converts x509.ExtKeyUsage array to string array
func extractExtKeyUsage(extUsages []x509.ExtKeyUsage) []string {
	var usages []string

	for _, usage := range extUsages {
		switch usage {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usages = append(usages, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usages = append(usages, "MicrosoftKernelCodeSigning")
		}
	}

	return usages
}

// getPublicKeySize returns the size of the public key in bits
func getPublicKeySize(cert *x509.Certificate) int32 {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return int32(pub.N.BitLen())
	case *dsa.PublicKey:
		return int32(pub.P.BitLen())
	case *ecdsa.PublicKey:
		return int32(pub.Curve.Params().BitSize)
	default:
		return 0
	}
}

// formatSerialNumber formats the certificate serial number as hex string
func formatSerialNumber(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return fmt.Sprintf("%X", serial)
}

// isWeakSignatureAlgorithm checks if the signature algorithm is considered weak
func isWeakSignatureAlgorithm(alg x509.SignatureAlgorithm) bool {
	weakAlgorithms := map[x509.SignatureAlgorithm]bool{
		x509.MD2WithRSA:    true,
		x509.MD5WithRSA:    true,
		x509.SHA1WithRSA:   true,
		x509.DSAWithSHA1:   true,
		x509.ECDSAWithSHA1: true,
	}
	return weakAlgorithms[alg]
}

// isShortKeySize checks if the key size is considered too short for modern security
func isShortKeySize(alg x509.PublicKeyAlgorithm, keySize int32) bool {
	switch alg {
	case x509.RSA:
		// RSA keys should be at least 2048 bits
		return keySize < 2048
	case x509.DSA:
		// DSA keys should be at least 2048 bits
		return keySize < 2048
	case x509.ECDSA:
		// ECDSA keys should be at least 224 bits
		return keySize < 224
	default:
		return false
	}
}
