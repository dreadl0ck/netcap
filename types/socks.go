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

const (
	fieldSOCKSCommandName          = "CommandName"
	fieldSOCKSAddressType          = "AddressType"
	fieldSOCKSAddressTypeName      = "AddressTypeName"
	fieldSOCKSDestinationAddress   = "DestinationAddress"
	fieldSOCKSDestinationPort      = "DestinationPort"
	fieldSOCKSAuthMethodName       = "AuthMethodName"
	fieldSOCKSAuthSuccess          = "AuthSuccess"
	fieldSOCKSReplyCode            = "ReplyCode"
	fieldSOCKSReplyCodeName        = "ReplyCodeName"
	fieldSOCKSBoundAddress         = "BoundAddress"
	fieldSOCKSBoundPort            = "BoundPort"
	fieldSOCKSUserID               = "UserID"
	fieldSOCKSIsRequest            = "IsRequest"
	fieldSOCKSIsHandshake          = "IsHandshake"
	fieldSOCKSConnectionSuccessful = "ConnectionSuccessful"
	fieldSOCKSTargetCategory       = "TargetCategory"
	fieldSOCKSIsAnonymous          = "IsAnonymous"
)

var fieldsSOCKS = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldVersion,
	fieldCommand,
	fieldSOCKSCommandName,
	fieldSOCKSAddressType,
	fieldSOCKSAddressTypeName,
	fieldSOCKSDestinationAddress,
	fieldSOCKSDestinationPort,
	fieldSOCKSAuthMethodName,
	fieldUsername,
	fieldSOCKSAuthSuccess,
	fieldSOCKSReplyCode,
	fieldSOCKSReplyCodeName,
	fieldSOCKSBoundAddress,
	fieldSOCKSBoundPort,
	fieldSOCKSIsRequest,
	fieldSOCKSIsHandshake,
	fieldSOCKSConnectionSuccessful,
	fieldSOCKSIsAnonymous,
}

// CSVHeader returns the CSV header for the audit record.
func (s *SOCKS) CSVHeader() []string {
	return filter(fieldsSOCKS)
}

// CSVRecord returns the CSV record for the audit record.
func (s *SOCKS) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		s.SrcIP,
		s.DstIP,
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
		formatInt32(s.Version),
		formatInt32(s.Command),
		s.CommandName,
		formatInt32(s.AddressType),
		s.AddressTypeName,
		s.DestinationAddress,
		formatInt32(s.DestinationPort),
		s.AuthMethodName,
		s.Username,
		strconv.FormatBool(s.AuthSuccess),
		formatInt32(s.ReplyCode),
		s.ReplyCodeName,
		s.BoundAddress,
		formatInt32(s.BoundPort),
		strconv.FormatBool(s.IsRequest),
		strconv.FormatBool(s.IsHandshake),
		strconv.FormatBool(s.ConnectionSuccessful),
		strconv.FormatBool(s.IsAnonymous),
	})
}

// Time returns the timestamp associated with the audit record.
func (s *SOCKS) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (s *SOCKS) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	s.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(s)
}

var socksMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SOCKS.String()),
		Help: Type_NC_SOCKS.String() + " audit records",
	},
	fieldsSOCKS[1:],
)

// Inc increments the metrics for the audit record.
func (s *SOCKS) Inc() {
	socksMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *SOCKS) SetPacketContext(ctx *PacketContext) {
	s.SrcIP = ctx.SrcIP
	s.DstIP = ctx.DstIP
	s.SrcPort = ctx.SrcPort
	s.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (s *SOCKS) Src() string {
	return s.SrcIP
}

// Dst returns the destination address of the audit record.
func (s *SOCKS) Dst() string {
	return s.DstIP
}

var socksEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (s *SOCKS) Encode() []string {
	return filter([]string{
		socksEncoder.Int64(fieldTimestamp, s.Timestamp),
		socksEncoder.String(fieldSrcIP, s.SrcIP),
		socksEncoder.String(fieldDstIP, s.DstIP),
		socksEncoder.Int32(fieldSrcPort, s.SrcPort),
		socksEncoder.Int32(fieldDstPort, s.DstPort),
		socksEncoder.Int32(fieldVersion, s.Version),
		socksEncoder.Int32(fieldCommand, s.Command),
		socksEncoder.String(fieldSOCKSCommandName, s.CommandName),
		socksEncoder.Int32(fieldSOCKSAddressType, s.AddressType),
		socksEncoder.String(fieldSOCKSAddressTypeName, s.AddressTypeName),
		socksEncoder.String(fieldSOCKSDestinationAddress, s.DestinationAddress),
		socksEncoder.Int32(fieldSOCKSDestinationPort, s.DestinationPort),
		socksEncoder.String(fieldSOCKSAuthMethodName, s.AuthMethodName),
		socksEncoder.String(fieldUsername, s.Username),
		socksEncoder.Bool(s.AuthSuccess),
		socksEncoder.Int32(fieldSOCKSReplyCode, s.ReplyCode),
		socksEncoder.String(fieldSOCKSReplyCodeName, s.ReplyCodeName),
		socksEncoder.String(fieldSOCKSBoundAddress, s.BoundAddress),
		socksEncoder.Int32(fieldSOCKSBoundPort, s.BoundPort),
		socksEncoder.Bool(s.IsRequest),
		socksEncoder.Bool(s.IsHandshake),
		socksEncoder.Bool(s.ConnectionSuccessful),
		socksEncoder.Bool(s.IsAnonymous),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *SOCKS) Analyze() {}

// NetcapType returns the type of the current audit record
func (s *SOCKS) NetcapType() Type {
	return Type_NC_SOCKS
}
