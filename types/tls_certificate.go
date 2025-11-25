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

package types

import (
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldChainIndex             = "ChainIndex"
	fieldSubjectCommonName      = "SubjectCommonName"
	fieldSubjectAltNames        = "SubjectAltNames"
	fieldSubjectOrganization    = "SubjectOrganization"
	fieldSubjectCountry         = "SubjectCountry"
	fieldSubjectLocality        = "SubjectLocality"
	fieldSubjectProvince        = "SubjectProvince"
	fieldIssuerCommonName       = "IssuerCommonName"
	fieldIssuerOrganization     = "IssuerOrganization"
	fieldIssuerCountry          = "IssuerCountry"
	fieldNotBefore              = "NotBefore"
	fieldNotAfter               = "NotAfter"
	fieldIsExpired              = "IsExpired"
	fieldIsSelfSigned           = "IsSelfSigned"
	fieldDaysUntilExpiration    = "DaysUntilExpiration"
	fieldIsNotYetValid          = "IsNotYetValid"
	fieldHasWeakSignature       = "HasWeakSignature"
	fieldHasShortKeySize        = "HasShortKeySize"
	fieldSignatureAlgorithm     = "SignatureAlgorithm"
	fieldPublicKeyAlgorithm     = "PublicKeyAlgorithm"
	fieldPublicKeySize          = "PublicKeySize"
	fieldSerialNumber           = "SerialNumber"
	fieldSHA256Fingerprint      = "SHA256Fingerprint"
	fieldSHA1Fingerprint        = "SHA1Fingerprint"
	fieldKeyUsage               = "KeyUsage"
	fieldExtKeyUsage            = "ExtKeyUsage"
	fieldIsCA                   = "IsCA"
	fieldMaxPathLen             = "MaxPathLen"
	fieldSeenCount              = "SeenCount"
)

var fieldsTLSCertificate = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcMAC,
	fieldDstMAC,
	fieldSrcPort,
	fieldDstPort,
	fieldChainIndex,
	fieldSubjectCommonName,
	fieldSubjectAltNames,
	fieldSubjectOrganization,
	fieldSubjectCountry,
	fieldSubjectLocality,
	fieldSubjectProvince,
	fieldIssuerCommonName,
	fieldIssuerOrganization,
	fieldIssuerCountry,
	fieldNotBefore,
	fieldNotAfter,
	fieldIsExpired,
	fieldIsSelfSigned,
	fieldDaysUntilExpiration,
	fieldIsNotYetValid,
	fieldHasWeakSignature,
	fieldHasShortKeySize,
	fieldSignatureAlgorithm,
	fieldPublicKeyAlgorithm,
	fieldPublicKeySize,
	fieldSerialNumber,
	fieldVersion,
	fieldSHA256Fingerprint,
	fieldSHA1Fingerprint,
	fieldKeyUsage,
	fieldExtKeyUsage,
	fieldIsCA,
	fieldMaxPathLen,
	fieldSeenCount,
}

// CSVHeader returns the CSV header for the audit record
func (t *TLSCertificate) CSVHeader() []string {
	return filter(fieldsTLSCertificate)
}

// CSVRecord returns the CSV record for the audit record
func (t *TLSCertificate) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(t.Timestamp),
		t.SrcIP,
		t.DstIP,
		t.SrcMAC,
		t.DstMAC,
		formatInt32(t.SrcPort),
		formatInt32(t.DstPort),
		formatInt32(t.ChainIndex),
		t.SubjectCommonName,
		join(t.SubjectAltNames...),
		t.SubjectOrganization,
		t.SubjectCountry,
		t.SubjectLocality,
		t.SubjectProvince,
		t.IssuerCommonName,
		t.IssuerOrganization,
		t.IssuerCountry,
		formatTimestamp(t.NotBefore),
		formatTimestamp(t.NotAfter),
		strconv.FormatBool(t.IsExpired),
		strconv.FormatBool(t.IsSelfSigned),
		formatInt64(t.DaysUntilExpiration),
		strconv.FormatBool(t.IsNotYetValid),
		strconv.FormatBool(t.HasWeakSignature),
		strconv.FormatBool(t.HasShortKeySize),
		t.SignatureAlgorithm,
		t.PublicKeyAlgorithm,
		formatInt32(t.PublicKeySize),
		t.SerialNumber,
		formatInt32(t.Version),
		t.SHA256Fingerprint,
		t.SHA1Fingerprint,
		join(t.KeyUsage...),
		join(t.ExtKeyUsage...),
		strconv.FormatBool(t.IsCA),
		formatInt32(t.MaxPathLen),
		formatInt64(t.SeenCount),
	})
}

// Time returns the timestamp associated with the audit record
func (t *TLSCertificate) Time() int64 {
	return t.Timestamp
}

// JSON returns the JSON representation of the audit record
func (t *TLSCertificate) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	t.Timestamp /= int64(time.Millisecond)
	t.NotBefore /= int64(time.Millisecond)
	t.NotAfter /= int64(time.Millisecond)
	t.FirstSeen /= int64(time.Millisecond)
	t.LastSeen /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(t)
}

var tlsCertificateMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_TLSCertificate.String()),
		Help: Type_NC_TLSCertificate.String() + " audit records",
	},
	fieldsTLSCertificate[1:],
)

// Inc increments the metrics for the audit record
func (t *TLSCertificate) Inc() {
	tlsCertificateMetric.WithLabelValues(t.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record
func (t *TLSCertificate) SetPacketContext(*PacketContext) {
	// Not applicable for stream-level records
}

// Src returns the source address of the audit record
func (t *TLSCertificate) Src() string {
	return t.SrcIP
}

// Dst returns the destination address of the audit record
func (t *TLSCertificate) Dst() string {
	return t.DstIP
}

func init() {
	prometheus.MustRegister(tlsCertificateMetric)
}

