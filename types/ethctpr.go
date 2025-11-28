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
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldFunction      = "Function"
	fieldReceiptNumber = "ReceiptNumber"
)

var fieldsEthernetCTPReply = []string{
	fieldTimestamp,
	fieldFunction,      // int32
	fieldReceiptNumber, // int32
	//fieldData,          // bytes
}

// CSVHeader returns the CSV header for the audit record.
func (ectpr *EthernetCTPReply) CSVHeader() []string {
	return filter(fieldsEthernetCTPReply)
}

// CSVRecord returns the CSV record for the audit record.
func (ectpr *EthernetCTPReply) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(ectpr.Timestamp),
		formatInt32(ectpr.Function),
		formatInt32(ectpr.ReceiptNumber),
		//hex.EncodeToString(ectpr.Data),
	})
}

// Time returns the timestamp associated with the audit record.
func (ectpr *EthernetCTPReply) Time() int64 {
	return ectpr.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (ectpr *EthernetCTPReply) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	ectpr.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(ectpr)
}

var ethernetCTPReplyMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_EthernetCTPReply.String()),
		Help: Type_NC_EthernetCTPReply.String() + " audit records",
	},
	fieldsEthernetCTPReply[1:],
)

// Inc increments the metrics for the audit record.
func (ectpr *EthernetCTPReply) Inc() {
	ethernetCTPReplyMetric.WithLabelValues(ectpr.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (ectpr *EthernetCTPReply) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (ectpr *EthernetCTPReply) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (ectpr *EthernetCTPReply) Dst() string {
	return ""
}

var ethCTPReplyEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (ectpr *EthernetCTPReply) Encode() []string {
	return filter([]string{
		ethCTPReplyEncoder.Int64(fieldTimestamp, ectpr.Timestamp),
		ethCTPReplyEncoder.Int32(fieldFunction, ectpr.Function),
		ethCTPReplyEncoder.Int32(fieldReceiptNumber, ectpr.ReceiptNumber),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (ectpr *EthernetCTPReply) Analyze() {}

// NetcapType returns the type of the current audit record
func (ectpr *EthernetCTPReply) NetcapType() Type {
	return Type_NC_EthernetCTPReply
}
