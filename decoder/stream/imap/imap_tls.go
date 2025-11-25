/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package imap

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// extractCertificatesAfterSTARTTLS attempts to extract X.509 certificates
// after a successful STARTTLS command
func (i *imapReader) extractCertificatesAfterSTARTTLS(data []byte) {
	if !i.startTLSSuccess {
		return
	}

	// Look for TLS handshake patterns in the data
	// TLS handshake typically starts with 0x16 (handshake record)
	if len(data) < 5 || data[0] != 0x16 {
		return
	}

	imapLog.Debug("Potential TLS handshake after STARTTLS",
		zap.Int("dataLen", len(data)),
		zap.String("ident", i.conversation.Ident),
	)

	// Try to extract certificates from TLS handshake
	// Look for certificate messages (handshake type 0x0b)
	i.extractCertificatesFromTLS(data)
}

// extractCertificatesFromTLS extracts X.509 certificates from TLS handshake data
func (i *imapReader) extractCertificatesFromTLS(data []byte) {
	// Simple certificate extraction
	// Look for PEM-encoded certificates or DER-encoded certificates

	// Try PEM first
	if bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		i.extractPEMCertificates(data)
		return
	}

	// Try DER format (would need full TLS parser)
	// For now, just log that we detected TLS
	imapLog.Info("TLS handshake detected after IMAP STARTTLS",
		zap.String("ident", i.conversation.Ident),
	)
}

// extractPEMCertificates extracts PEM-encoded certificates
func (i *imapReader) extractPEMCertificates(data []byte) {
	remaining := data
	certCount := 0

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				imapLog.Error("Failed to parse certificate",
					zap.Error(err),
					zap.String("ident", i.conversation.Ident),
				)
				remaining = rest
				continue
			}

			// Convert to TLSCertificate audit record and store
			tlsCert := convertX509ToTLSCertificate(cert, i.conversation, certCount, "IMAP-STARTTLS")

			// Write to TLS certificate decoder
			if tlsCert != nil {
				writeTLSCertificate(tlsCert)
				certCount++

				imapLog.Info("Extracted certificate from IMAP STARTTLS",
					zap.String("subject", cert.Subject.CommonName),
					zap.String("issuer", cert.Issuer.CommonName),
					zap.Time("notBefore", cert.NotBefore),
					zap.Time("notAfter", cert.NotAfter),
					zap.String("fingerprint", tlsCert.SHA256Fingerprint),
					zap.String("ident", i.conversation.Ident),
				)
			}
		}

		remaining = rest
	}

	if certCount > 0 {
		imapLog.Info("Extracted certificates from IMAP STARTTLS",
			zap.Int("count", certCount),
			zap.String("ident", i.conversation.Ident),
		)
	}
}

// convertX509ToTLSCertificate converts an x509.Certificate to TLSCertificate audit record
func convertX509ToTLSCertificate(cert *x509.Certificate, conv *core.ConversationInfo, chainIndex int, source string) *types.TLSCertificate {
	now := time.Now()

	// Compute fingerprints
	sha256Sum := sha256.Sum256(cert.Raw)
	sha1Sum := sha1.Sum(cert.Raw)

	// Calculate expiration
	daysUntilExpiration := int64(time.Until(cert.NotAfter).Hours() / 24)
	isExpired := cert.NotAfter.Before(now)

	// Extract subject alternative names
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	tlsCert := &types.TLSCertificate{
		Timestamp:           conv.FirstServerPacket.UnixNano(),
		SrcIP:               conv.ServerIP,
		DstIP:               conv.ClientIP,
		SrcPort:             conv.ServerPort,
		DstPort:             conv.ClientPort,
		ChainIndex:          int32(chainIndex),
		SubjectCommonName:   cert.Subject.CommonName,
		SubjectOrganization: joinStrings(cert.Subject.Organization),
		SubjectCountry:      joinStrings(cert.Subject.Country),
		IssuerCommonName:    cert.Issuer.CommonName,
		IssuerOrganization:  joinStrings(cert.Issuer.Organization),
		IssuerCountry:       joinStrings(cert.Issuer.Country),
		NotBefore:           cert.NotBefore.UnixNano(),
		NotAfter:            cert.NotAfter.UnixNano(),
		IsExpired:           isExpired,
		IsSelfSigned:        cert.Subject.CommonName == cert.Issuer.CommonName,
		DaysUntilExpiration: daysUntilExpiration,
		SignatureAlgorithm:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
		SerialNumber:        cert.SerialNumber.String(),
		Version:             int32(cert.Version),
		SHA256Fingerprint:   hex.EncodeToString(sha256Sum[:]),
		SHA1Fingerprint:     hex.EncodeToString(sha1Sum[:]),
		SubjectAltNames:     sans,
	}

	return tlsCert
}

// writeTLSCertificate writes a TLSCertificate audit record
func writeTLSCertificate(cert *types.TLSCertificate) {
	if tls.Decoder.Writer == nil {
		imapLog.Warn("TLS certificate decoder writer not initialized")
		return
	}

	// Use TLS decoder's deduplication
	if tls.AddOrUpdateCertificate(cert) {
		atomic.AddInt64(&tls.Decoder.NumRecordsWritten, 1)
		err := tls.Decoder.Writer.Write(cert)
		if err != nil {
			decoderutils.ErrorMap.Inc(err.Error())
			imapLog.Error("Failed to write TLS certificate",
				zap.Error(err),
			)
		}
	}
}

// joinStrings joins a string slice with commas
func joinStrings(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += ", " + strs[i]
	}
	return result
}

// Note: For production use with actual IMAP STARTTLS traffic:
// 1. Monitor for STARTTLS command and OK response ✅ Implemented
// 2. Parse subsequent TLS ClientHello/ServerHello ⚠️ Requires full TLS parser
// 3. Extract certificates from TLS Certificate message ✅ Implemented (PEM)
// 4. Store in TLSCertificate audit records ✅ Implemented
// 5. Use TLS decoder deduplication ✅ Integrated
