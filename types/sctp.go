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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/encoder"

	"github.com/prometheus/client_golang/prometheus"
)

const fieldVerificationTag = "VerificationTag"

var fieldsSCTP = []string{
	fieldTimestamp,
	fieldSrcPort,
	fieldDstPort,
	fieldVerificationTag,
	fieldChecksum,
	fieldSrcIP,
	fieldDstIP,
}

// CSVHeader returns the CSV header for the audit record.
func (s *SCTP) CSVHeader() []string {
	return filter(fieldsSCTP)
}

// CSVRecord returns the CSV record for the audit record.
func (s *SCTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
		strconv.FormatUint(uint64(s.VerificationTag), 10),
		strconv.FormatUint(uint64(s.Checksum), 10),
		s.SrcIP,
		s.DstIP,
	})
}

// Time returns the timestamp associated with the audit record.
func (s *SCTP) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (u *SCTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	u.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(u)
}

var sctpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SCTP.String()),
		Help: Type_NC_SCTP.String() + " audit records",
	},
	fieldsSCTP[1:],
)

// Inc increments the metrics for the audit record.
func (s *SCTP) Inc() {
	sctpMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *SCTP) SetPacketContext(ctx *PacketContext) {
	s.SrcIP = ctx.SrcIP
	s.DstIP = ctx.DstIP
}

// Src returns the source address of the audit record.
func (s *SCTP) Src() string {
	return s.SrcIP
}

// Dst returns the destination address of the audit record.
func (s *SCTP) Dst() string {
	return s.DstIP
}

var sctpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (s *SCTP) Encode() []string {
	return filter([]string{
		sctpEncoder.Int64(fieldTimestamp, s.Timestamp),
		sctpEncoder.Int32(fieldSrcPort, s.SrcPort),
		sctpEncoder.Int32(fieldDstPort, s.DstPort),
		sctpEncoder.Uint32(fieldVerificationTag, s.VerificationTag),
		sctpEncoder.Uint32(fieldChecksum, s.Checksum),
		sctpEncoder.String(fieldSrcIP, s.SrcIP),
		sctpEncoder.String(fieldDstIP, s.DstIP),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *SCTP) Analyze() {}

// NetcapType returns the type of the current audit record
func (s *SCTP) NetcapType() Type {
	return Type_NC_SCTP
}
