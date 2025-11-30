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

package types

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldQUICClientHelloQUICVersion                  = "QUICVersion"
	fieldQUICClientHelloIsIETFQUIC                   = "IsIETFQUIC"
	fieldQUICClientHelloDCID                         = "DCID"
	fieldQUICClientHelloSCID                         = "SCID"
	fieldQUICClientHelloSNI                          = "SNI"
	fieldQUICClientHelloALPNs                        = "ALPNs"
	fieldQUICClientHelloCipherSuites                 = "CipherSuites"
	fieldQUICClientHelloExtensions                   = "Extensions"
	fieldQUICClientHelloSupportedGroups              = "SupportedGroups"
	fieldQUICClientHelloSignatureAlgs                = "SignatureAlgs"
	fieldQUICClientHelloSupportedVersion             = "SupportedVersion"
	fieldQUICClientHelloUAID                         = "UAID"
	fieldQUICClientHelloCHLOTags                     = "CHLOTags"
	fieldQUICClientHelloTagValues                    = "TagValues"
	fieldQUICClientHelloJa4                          = "Ja4"
	fieldQUICClientHelloJa4Description               = "Ja4Description"
	fieldQUICClientHelloMaxIdleTimeout               = "MaxIdleTimeout"
	fieldQUICClientHelloInitialMaxData               = "InitialMaxData"
	fieldQUICClientHelloInitialMaxStreamDataBidiLocal = "InitialMaxStreamDataBidiLocal"
	fieldQUICClientHelloMaxUdpPayloadSize            = "MaxUdpPayloadSize"
	fieldQUICClientHelloRandom                       = "Random"
	fieldQUICClientHelloSessionID                    = "SessionID"
	fieldQUICClientHelloSupportedPoints              = "SupportedPoints"
	fieldQUICClientHelloCompressMethods              = "CompressMethods"
)

var fieldsQUICClientHello = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldQUICClientHelloQUICVersion,
	fieldQUICClientHelloIsIETFQUIC,
	fieldQUICClientHelloDCID,
	fieldQUICClientHelloSCID,
	fieldQUICClientHelloSNI,
	fieldQUICClientHelloALPNs,
	fieldQUICClientHelloCipherSuites,
	fieldQUICClientHelloExtensions,
	fieldQUICClientHelloSupportedGroups,
	fieldQUICClientHelloSignatureAlgs,
	fieldQUICClientHelloSupportedVersion,
	fieldQUICClientHelloUAID,
	fieldQUICClientHelloCHLOTags,
	fieldQUICClientHelloJa4,
	fieldQUICClientHelloJa4Description,
	fieldQUICClientHelloMaxIdleTimeout,
	fieldQUICClientHelloInitialMaxData,
	fieldQUICClientHelloInitialMaxStreamDataBidiLocal,
	fieldQUICClientHelloMaxUdpPayloadSize,
}

// CSVHeader returns the CSV header for the audit record.
func (q *QUICClientHello) CSVHeader() []string {
	return filter(fieldsQUICClientHello)
}

// CSVRecord returns the CSV record for the audit record.
func (q *QUICClientHello) CSVRecord() []string {
	// Convert TagValues map to string representation
	tagValuesStr := ""
	if q.TagValues != nil {
		pairs := make([]string, 0, len(q.TagValues))
		for k, v := range q.TagValues {
			pairs = append(pairs, k+"="+v)
		}
		tagValuesStr = strings.Join(pairs, ";")
	}

	return filter([]string{
		formatTimestamp(q.Timestamp),
		q.SrcIP,
		q.DstIP,
		formatInt32(q.SrcPort),
		formatInt32(q.DstPort),
		q.QUICVersion,
		strconv.FormatBool(q.IsIETFQUIC),
		hex.EncodeToString(q.DCID),
		hex.EncodeToString(q.SCID),
		q.SNI,
		strings.Join(q.ALPNs, "|"),
		joinInts(q.CipherSuites),
		joinInts(q.Extensions),
		joinInts(q.SupportedGroups),
		joinInts(q.SignatureAlgs),
		formatInt32(q.SupportedVersion),
		q.UAID,
		strings.Join(q.CHLOTags, "|"),
		tagValuesStr,
		q.Ja4,
		q.Ja4Description,
		strconv.FormatInt(q.MaxIdleTimeout, 10),
		strconv.FormatInt(q.InitialMaxData, 10),
		strconv.FormatInt(q.InitialMaxStreamDataBidiLocal, 10),
		strconv.FormatInt(q.MaxUdpPayloadSize, 10),
	})
}

// Time returns the timestamp associated with the audit record.
func (q *QUICClientHello) Time() int64 {
	return q.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (q *QUICClientHello) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	q.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(q)
}

var quicClientHelloMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_QUICClientHello.String()),
		Help: Type_NC_QUICClientHello.String() + " audit records",
	},
	fieldsQUICClientHello[1:],
)

// Inc increments the metrics for the audit record.
func (q *QUICClientHello) Inc() {
	quicClientHelloMetric.WithLabelValues(q.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (q *QUICClientHello) SetPacketContext(ctx *PacketContext) {
	q.SrcIP = ctx.SrcIP
	q.DstIP = ctx.DstIP
	q.SrcPort = ctx.SrcPort
	q.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (q *QUICClientHello) Src() string {
	return q.SrcIP
}

// Dst returns the destination address of the audit record.
func (q *QUICClientHello) Dst() string {
	return q.DstIP
}

var quicClientHelloEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (q *QUICClientHello) Encode() []string {
	return filter([]string{
		quicClientHelloEncoder.Int64(fieldTimestamp, q.Timestamp),
		quicClientHelloEncoder.String(fieldSrcIP, q.SrcIP),
		quicClientHelloEncoder.String(fieldDstIP, q.DstIP),
		quicClientHelloEncoder.Int32(fieldSrcPort, q.SrcPort),
		quicClientHelloEncoder.Int32(fieldDstPort, q.DstPort),
		quicClientHelloEncoder.String(fieldQUICClientHelloQUICVersion, q.QUICVersion),
		quicClientHelloEncoder.Bool(q.IsIETFQUIC),
		quicClientHelloEncoder.String(fieldQUICClientHelloDCID, hex.EncodeToString(q.DCID)),
		quicClientHelloEncoder.String(fieldQUICClientHelloSCID, hex.EncodeToString(q.SCID)),
		quicClientHelloEncoder.String(fieldQUICClientHelloSNI, q.SNI),
		quicClientHelloEncoder.String(fieldQUICClientHelloALPNs, strings.Join(q.ALPNs, "|")),
		quicClientHelloEncoder.String(fieldQUICClientHelloCipherSuites, joinInts(q.CipherSuites)),
		quicClientHelloEncoder.String(fieldQUICClientHelloExtensions, joinInts(q.Extensions)),
		quicClientHelloEncoder.String(fieldQUICClientHelloSupportedGroups, joinInts(q.SupportedGroups)),
		quicClientHelloEncoder.String(fieldQUICClientHelloSignatureAlgs, joinInts(q.SignatureAlgs)),
		quicClientHelloEncoder.Int32(fieldQUICClientHelloSupportedVersion, q.SupportedVersion),
		quicClientHelloEncoder.String(fieldQUICClientHelloUAID, q.UAID),
		quicClientHelloEncoder.String(fieldQUICClientHelloCHLOTags, strings.Join(q.CHLOTags, "|")),
		quicClientHelloEncoder.String(fieldQUICClientHelloJa4, q.Ja4),
		quicClientHelloEncoder.String(fieldQUICClientHelloJa4Description, q.Ja4Description),
		quicClientHelloEncoder.Int64(fieldQUICClientHelloMaxIdleTimeout, q.MaxIdleTimeout),
		quicClientHelloEncoder.Int64(fieldQUICClientHelloInitialMaxData, q.InitialMaxData),
		quicClientHelloEncoder.Int64(fieldQUICClientHelloInitialMaxStreamDataBidiLocal, q.InitialMaxStreamDataBidiLocal),
		quicClientHelloEncoder.Int64(fieldQUICClientHelloMaxUdpPayloadSize, q.MaxUdpPayloadSize),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (q *QUICClientHello) Analyze() {}

// NetcapType returns the type of the current audit record.
func (q *QUICClientHello) NetcapType() Type {
	return Type_NC_QUICClientHello
}

// DCIDHex returns the Destination Connection ID as a hex string.
func (q *QUICClientHello) DCIDHex() string {
	if q.DCID == nil {
		return ""
	}
	return hex.EncodeToString(q.DCID)
}

// SCIDHex returns the Source Connection ID as a hex string.
func (q *QUICClientHello) SCIDHex() string {
	if q.SCID == nil {
		return ""
	}
	return hex.EncodeToString(q.SCID)
}

// RandomHex returns the TLS random bytes as a hex string.
func (q *QUICClientHello) RandomHex() string {
	if q.Random == nil {
		return ""
	}
	return hex.EncodeToString(q.Random)
}

// SessionIDHex returns the session ID as a hex string.
func (q *QUICClientHello) SessionIDHex() string {
	if q.SessionID == nil {
		return ""
	}
	return hex.EncodeToString(q.SessionID)
}

