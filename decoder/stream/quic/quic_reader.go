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

package quic

import (
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/internal/ja4"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type quicReader struct {
	conversation *core.ConversationInfo
}

// New returns a new QUIC reader.
func (q *quicReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &quicReader{
		conversation: conversation,
	}
}

// Decode parses QUIC packets from the stream and extracts ClientHello information.
func (q *quicReader) Decode() {
	if Decoder.Writer == nil {
		quicLog.Error("QUIC Decoder.Writer is nil")
		return
	}

	quicLog.Debug("Decoding QUIC conversation",
		zap.String("clientIP", q.conversation.ClientIP),
		zap.Int32("clientPort", q.conversation.ClientPort),
		zap.String("serverIP", q.conversation.ServerIP),
		zap.Int32("serverPort", q.conversation.ServerPort),
		zap.Int("numPackets", len(q.conversation.Data)),
	)

	// Process each packet in the conversation
	for _, data := range q.conversation.Data {
		payload := data.Raw()
		if len(payload) < 5 {
			continue
		}

		// Try to parse as IETF QUIC first
		if IsIETFQUICPacket(payload) {
			q.parseIETFQUIC(payload, data.CaptureInfo().Timestamp.UnixNano())
			continue
		}

		// Try to parse as gQUIC
		if IsGQUICPacket(payload) {
			q.parseGQUIC(payload, data.CaptureInfo().Timestamp.UnixNano())
			continue
		}
	}
}

// parseIETFQUIC parses an IETF QUIC Initial packet and writes a QUICClientHello record.
func (q *quicReader) parseIETFQUIC(payload []byte, timestamp int64) {
	clientHello, err := ParseIETFQUICInitial(payload)
	if err != nil {
		quicLog.Debug("Failed to parse IETF QUIC Initial",
			zap.Error(err),
			zap.Int("payloadLen", len(payload)),
		)
		return
	}
	if clientHello == nil {
		return // Not an Initial packet
	}

	// Only process if we got useful data (SNI or cipher suites)
	if clientHello.SNI == "" && len(clientHello.CipherSuites) == 0 {
		quicLog.Debug("IETF QUIC Initial parsed but no ClientHello data extracted")
		return
	}

	quicLog.Debug("Parsed IETF QUIC ClientHello",
		zap.String("SNI", clientHello.SNI),
		zap.Int("numCipherSuites", len(clientHello.CipherSuites)),
		zap.Strings("ALPNs", clientHello.ALPNs),
	)

	// Convert cipher suites to int32
	cipherSuites := make([]int32, len(clientHello.CipherSuites))
	for i, cs := range clientHello.CipherSuites {
		cipherSuites[i] = int32(cs)
	}

	// Convert extensions to int32
	extensions := make([]int32, len(clientHello.Extensions))
	for i, ext := range clientHello.Extensions {
		extensions[i] = int32(ext)
	}

	// Convert supported groups to int32
	supportedGroups := make([]int32, len(clientHello.SupportedGroups))
	for i, sg := range clientHello.SupportedGroups {
		supportedGroups[i] = int32(sg)
	}

	// Convert signature algorithms to int32
	signatureAlgs := make([]int32, len(clientHello.SignatureAlgs))
	for i, sa := range clientHello.SignatureAlgs {
		signatureAlgs[i] = int32(sa)
	}

	// Compute JA4 fingerprint with QUIC flag
	var supportedVersion uint16
	if len(clientHello.SupportedVersions) > 0 {
		supportedVersion = clientHello.SupportedVersions[0]
	}

	ja4Fingerprint := ja4.ComputeJA4(&ja4.ClientHelloData{
		Version:             clientHello.TLSVersion,
		CipherSuites:        clientHello.CipherSuites,
		Extensions:          clientHello.Extensions,
		SNI:                 clientHello.SNI,
		ALPNs:               clientHello.ALPNs,
		SupportedVers:       supportedVersion,
		IsQUIC:              true, // This is QUIC, so JA4 will use 'q' prefix
		SignatureAlgorithms: clientHello.SignatureAlgs,
	})

	// Lookup JA4 fingerprint in database for enrichment
	ja4Description := resolvers.LookupJA4(ja4Fingerprint)

	// Determine version string
	versionStr := "1"
	if clientHello.Version == 0x6b3343cf {
		versionStr = "2"
	} else if clientHello.Version >= 0xff000000 && clientHello.Version <= 0xff00001d {
		versionStr = "draft"
	}

	record := &types.QUICClientHello{
		Timestamp:         timestamp,
		SrcIP:             q.conversation.ClientIP,
		DstIP:             q.conversation.ServerIP,
		SrcPort:           int32(q.conversation.ClientPort),
		DstPort:           int32(q.conversation.ServerPort),
		QUICVersion:       versionStr,
		IsIETFQUIC:        true,
		DCID:              clientHello.DCID,
		SCID:              clientHello.SCID,
		SNI:               clientHello.SNI,
		ALPNs:             clientHello.ALPNs,
		CipherSuites:      cipherSuites,
		Extensions:        extensions,
		SupportedGroups:   supportedGroups,
		SignatureAlgs:     signatureAlgs,
		SupportedVersion:  int32(supportedVersion),
		Random:            clientHello.Random,
		SessionID:         clientHello.SessionID,
		CompressMethods:   convertBytesToInt32(clientHello.CompressionMethods),
		Ja4:               ja4Fingerprint,
		Ja4Description:    ja4Description,
		MaxIdleTimeout:    int64(clientHello.MaxIdleTimeout),
		InitialMaxData:    int64(clientHello.InitialMaxData),
		InitialMaxStreamDataBidiLocal: int64(clientHello.InitialMaxStreamDataBidiLocal),
		MaxUdpPayloadSize: int64(clientHello.MaxUDPPayloadSize),
		CommunityID:       q.conversation.CommunityID,
	}

	err = Decoder.Writer.Write(record)
	if err != nil {
		quicLog.Error("failed to write IETF QUIC ClientHello record", zap.Error(err))
	} else {
		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		quicLog.Info("IETF QUIC ClientHello extracted",
			zap.String("sni", clientHello.SNI),
			zap.String("ja4", ja4Fingerprint),
			zap.Strings("alpns", clientHello.ALPNs),
		)
	}
}

// parseGQUIC parses a gQUIC packet and writes a QUICClientHello record.
func (q *quicReader) parseGQUIC(payload []byte, timestamp int64) {
	clientHello, err := ParseGQUICClientHello(payload)
	if err != nil || clientHello == nil {
		quicLog.Debug("Failed to parse gQUIC CHLO",
			zap.Error(err),
			zap.Int("payloadLen", len(payload)),
		)
		return
	}

	// Only process if we got useful data
	if clientHello.SNI == "" && len(clientHello.Tags) == 0 {
		quicLog.Debug("gQUIC CHLO parsed but no useful data extracted")
		return
	}

	// For gQUIC, we can still compute a JA4-like fingerprint
	// gQUIC uses different cryptographic negotiation, so we simulate TLS-like data
	var ja4Fingerprint string
	if len(clientHello.Tags) > 0 {
		// Create a pseudo-fingerprint based on gQUIC tags
		// For now, we'll create a simplified fingerprint
		ja4Fingerprint = computeGQUICFingerprint(clientHello)
	}

	record := &types.QUICClientHello{
		Timestamp:   timestamp,
		SrcIP:       q.conversation.ClientIP,
		DstIP:       q.conversation.ServerIP,
		SrcPort:     int32(q.conversation.ClientPort),
		DstPort:     int32(q.conversation.ServerPort),
		QUICVersion: clientHello.Version,
		IsIETFQUIC:  false,
		DCID:        clientHello.CID,
		SNI:         clientHello.SNI,
		UAID:        clientHello.UAID,
		CHLOTags:    clientHello.Tags,
		TagValues:   clientHello.TagValues,
		Ja4:         ja4Fingerprint,
		CommunityID: q.conversation.CommunityID,
	}

	err = Decoder.Writer.Write(record)
	if err != nil {
		quicLog.Error("failed to write gQUIC ClientHello record", zap.Error(err))
	} else {
		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		quicLog.Info("gQUIC CHLO extracted",
			zap.String("sni", clientHello.SNI),
			zap.String("uaid", clientHello.UAID),
			zap.String("version", clientHello.Version),
			zap.Strings("tags", clientHello.Tags),
		)
	}
}

// computeGQUICFingerprint creates a fingerprint for gQUIC based on CHLO tags.
// This is a simplified version since gQUIC doesn't use TLS directly.
func computeGQUICFingerprint(chlo *GQUICClientHello) string {
	// Format: q{version}{tag_count:2d}{aead}{kexs}
	// This is a custom fingerprint format for gQUIC
	
	tagCount := len(chlo.Tags)
	if tagCount > 99 {
		tagCount = 99
	}

	// Get AEAD and KEXS values if available
	aead := "00"
	if v, ok := chlo.TagValues["AEAD"]; ok && len(v) >= 2 {
		aead = v[:2]
	}

	kexs := "00"
	if v, ok := chlo.TagValues["KEXS"]; ok && len(v) >= 2 {
		kexs = v[:2]
	}

	// Create fingerprint
	// Format: q_gquic_{version}_{tag_count}_{aead}_{kexs}
	version := chlo.Version
	if len(version) > 4 {
		version = version[:4]
	}

	return "q_gquic_" + version + "_" + 
		padInt(tagCount, 2) + "_" + 
		aead + "_" + kexs
}

// padInt pads an integer to the specified width.
func padInt(n, width int) string {
	s := ""
	for n > 0 || len(s) < width {
		s = string('0'+byte(n%10)) + s
		n /= 10
	}
	if len(s) > width {
		s = s[len(s)-width:]
	}
	return s
}

// convertBytesToInt32 converts a byte slice to an int32 slice.
func convertBytesToInt32(data []byte) []int32 {
	result := make([]int32, len(data))
	for i, b := range data {
		result[i] = int32(b)
	}
	return result
}

// GetQUICVersionString returns a human-readable version string for QUIC versions.
func GetQUICVersionString(version uint32) string {
	switch version {
	case 0x00000001:
		return "IETF QUIC v1"
	case 0x6b3343cf:
		return "IETF QUIC v2"
	case 0x00000000:
		return "Version Negotiation"
	default:
		if version >= 0xff000000 && version <= 0xff00001d {
			return "IETF QUIC Draft"
		}
		// Check for gQUIC
		vBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(vBytes, version)
		if vBytes[0] == 'Q' {
			return "gQUIC " + string(vBytes)
		}
		return "Unknown"
	}
}

