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
	fieldQUICIsLongHeader      = "IsLongHeader"
	fieldQUICHeaderType        = "HeaderType"
	fieldQUICVersion           = "Version"
	fieldQUICDCID              = "DCID"
	fieldQUICSCID              = "SCID"
	fieldQUICPacketNumber      = "PacketNumber"
	fieldQUICIsIETFQUIC        = "IsIETFQUIC"
	fieldQUICIsGQUIC           = "IsGQUIC"
	fieldQUICSupportedVersions = "SupportedVersions"
	fieldQUICPayloadLength     = "PayloadLength"
	fieldQUICTokenLength       = "TokenLength"
)

var fieldsQUIC = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldQUICIsLongHeader,
	fieldQUICHeaderType,
	fieldQUICVersion,
	fieldQUICDCID,
	fieldQUICSCID,
	fieldQUICPacketNumber,
	fieldQUICIsIETFQUIC,
	fieldQUICIsGQUIC,
	fieldQUICSupportedVersions,
	fieldQUICPayloadLength,
	fieldQUICTokenLength,
}

// CSVHeader returns the CSV header for the audit record.
func (q *QUIC) CSVHeader() []string {
	return filter(fieldsQUIC)
}

// CSVRecord returns the CSV record for the audit record.
func (q *QUIC) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(q.Timestamp),
		q.SrcIP,
		q.DstIP,
		formatInt32(q.SrcPort),
		formatInt32(q.DstPort),
		strconv.FormatBool(q.IsLongHeader),
		formatInt32(q.HeaderType),
		q.Version,
		hex.EncodeToString(q.DCID),
		hex.EncodeToString(q.SCID),
		formatInt32(q.PacketNumber),
		strconv.FormatBool(q.IsIETFQUIC),
		strconv.FormatBool(q.IsGQUIC),
		strings.Join(q.SupportedVersions, "|"),
		formatInt32(q.PayloadLength),
		formatInt32(q.TokenLength),
	})
}

// Time returns the timestamp associated with the audit record.
func (q *QUIC) Time() int64 {
	return q.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (q *QUIC) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	q.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(q)
}

var quicMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_QUIC.String()),
		Help: Type_NC_QUIC.String() + " audit records",
	},
	fieldsQUIC[1:],
)

// Inc increments the metrics for the audit record.
func (q *QUIC) Inc() {
	quicMetric.WithLabelValues(q.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (q *QUIC) SetPacketContext(ctx *PacketContext) {
	q.SrcIP = ctx.SrcIP
	q.DstIP = ctx.DstIP
	q.SrcPort = ctx.SrcPort
	q.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (q *QUIC) Src() string {
	return q.SrcIP
}

// Dst returns the destination address of the audit record.
func (q *QUIC) Dst() string {
	return q.DstIP
}

var quicEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration.
func (q *QUIC) Encode() []string {
	return filter([]string{
		quicEncoder.Int64(fieldTimestamp, q.Timestamp),
		quicEncoder.String(fieldSrcIP, q.SrcIP),
		quicEncoder.String(fieldDstIP, q.DstIP),
		quicEncoder.Int32(fieldSrcPort, q.SrcPort),
		quicEncoder.Int32(fieldDstPort, q.DstPort),
		quicEncoder.Bool(q.IsLongHeader),
		quicEncoder.Int32(fieldQUICHeaderType, q.HeaderType),
		quicEncoder.String(fieldQUICVersion, q.Version),
		quicEncoder.String(fieldQUICDCID, hex.EncodeToString(q.DCID)),
		quicEncoder.String(fieldQUICSCID, hex.EncodeToString(q.SCID)),
		quicEncoder.Int32(fieldQUICPacketNumber, q.PacketNumber),
		quicEncoder.Bool(q.IsIETFQUIC),
		quicEncoder.Bool(q.IsGQUIC),
		quicEncoder.String(fieldQUICSupportedVersions, strings.Join(q.SupportedVersions, "|")),
		quicEncoder.Int32(fieldQUICPayloadLength, q.PayloadLength),
		quicEncoder.Int32(fieldQUICTokenLength, q.TokenLength),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (q *QUIC) Analyze() {}

// NetcapType returns the type of the current audit record.
func (q *QUIC) NetcapType() Type {
	return Type_NC_QUIC
}

// DCIDHex returns the Destination Connection ID as a hex string.
func (q *QUIC) DCIDHex() string {
	if q.DCID == nil {
		return ""
	}
	return hex.EncodeToString(q.DCID)
}

// SCIDHex returns the Source Connection ID as a hex string.
func (q *QUIC) SCIDHex() string {
	if q.SCID == nil {
		return ""
	}
	return hex.EncodeToString(q.SCID)
}

// HeaderTypeName returns the human-readable name for the QUIC header type.
func (q *QUIC) HeaderTypeName() string {
	switch q.HeaderType {
	case 0:
		return "Initial"
	case 1:
		return "0-RTT"
	case 2:
		return "Handshake"
	case 3:
		return "Retry"
	default:
		return "Unknown"
	}
}

