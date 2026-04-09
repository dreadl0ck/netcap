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
	fieldGTPProtocolType    = "ProtocolType"
	fieldGTPMessageType     = "MessageType"
	fieldGTPMessageTypeName = "MessageTypeName"
	fieldGTPTEID            = "TEID"
	fieldGTPSequenceNumber  = "SequenceNumber"
	fieldGTPIsSignaling     = "IsSignaling"
	fieldGTPIMSI            = "IMSI"
	fieldGTPMSISDN          = "MSISDN"
	fieldGTPIMEI            = "IMEI"
	fieldGTPAPNName         = "APNName"
	fieldGTPPDNType         = "PDNType"
	fieldGTPPDNAddress      = "PDNAddress"
	fieldGTPSGWAddress      = "SGWAddress"
	fieldGTPPGWAddress      = "PGWAddress"
	fieldGTPEBI             = "EBI"
	fieldGTPQCI             = "QCI"
	fieldGTPTAI             = "TAI"
	fieldGTPECGI            = "ECGI"
	fieldGTPCause           = "Cause"
	fieldGTPCauseName       = "CauseName"
	fieldGTPRequestAccepted = "RequestAccepted"
	fieldGTPIsCreateSession = "IsCreateSession"
	fieldGTPIsDeleteSession = "IsDeleteSession"
	fieldGTPIsModifyBearer  = "IsModifyBearer"
	fieldGTPIsHandover      = "IsHandover"
	fieldGTPSecurityContext = "SecurityContext"
)

var fieldsGTP = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldVersion,
	fieldGTPProtocolType,
	fieldGTPMessageType,
	fieldGTPMessageTypeName,
	fieldLength,
	fieldGTPTEID,
	fieldGTPSequenceNumber,
	fieldGTPIsSignaling,
	fieldGTPIMSI,
	fieldGTPMSISDN,
	fieldGTPIMEI,
	fieldGTPAPNName,
	fieldGTPPDNType,
	fieldGTPPDNAddress,
	fieldGTPSGWAddress,
	fieldGTPPGWAddress,
	fieldGTPEBI,
	fieldGTPQCI,
	fieldGTPTAI,
	fieldGTPECGI,
	fieldGTPCause,
	fieldGTPCauseName,
	fieldGTPRequestAccepted,
	fieldGTPIsCreateSession,
	fieldGTPIsDeleteSession,
	fieldGTPIsModifyBearer,
	fieldGTPIsHandover,
	fieldGTPSecurityContext,
}

// CSVHeader returns the CSV header for the audit record.
func (g *GTP) CSVHeader() []string {
	return filter(fieldsGTP)
}

// CSVRecord returns the CSV record for the audit record.
func (g *GTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(g.Timestamp),
		g.SrcIP,
		g.DstIP,
		formatInt32(g.SrcPort),
		formatInt32(g.DstPort),
		formatInt32(g.Version),
		strconv.FormatBool(g.ProtocolType),
		formatInt32(g.MessageType),
		g.MessageTypeName,
		formatInt32(g.Length),
		formatUint32(g.TEID),
		formatInt32(g.SequenceNumber),
		strconv.FormatBool(g.IsSignaling),
		g.IMSI,
		g.MSISDN,
		g.IMEI,
		g.APNName,
		g.PDNType,
		g.PDNAddress,
		g.SGWAddress,
		g.PGWAddress,
		formatInt32(g.EBI),
		formatInt32(g.QCI),
		g.TAI,
		g.ECGI,
		formatInt32(g.Cause),
		g.CauseName,
		strconv.FormatBool(g.RequestAccepted),
		strconv.FormatBool(g.IsCreateSession),
		strconv.FormatBool(g.IsDeleteSession),
		strconv.FormatBool(g.IsModifyBearer),
		strconv.FormatBool(g.IsHandover),
		g.SecurityContext,
	})
}

// Time returns the timestamp associated with the audit record.
func (g *GTP) Time() int64 {
	return g.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (g *GTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	g.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(g)
}

var gtpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_GTP.String()),
		Help: Type_NC_GTP.String() + " audit records",
	},
	fieldsGTP[1:],
)

// Inc increments the metrics for the audit record.
func (g *GTP) Inc() {
	gtpMetric.WithLabelValues(g.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (g *GTP) SetPacketContext(ctx *PacketContext) {
	g.SrcIP = ctx.SrcIP
	g.DstIP = ctx.DstIP
	g.SrcPort = ctx.SrcPort
	g.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (g *GTP) Src() string {
	return g.SrcIP
}

// Dst returns the destination address of the audit record.
func (g *GTP) Dst() string {
	return g.DstIP
}

var gtpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (g *GTP) Encode() []string {
	return filter([]string{
		gtpEncoder.Int64(fieldTimestamp, g.Timestamp),
		gtpEncoder.String(fieldSrcIP, g.SrcIP),
		gtpEncoder.String(fieldDstIP, g.DstIP),
		gtpEncoder.Int32(fieldSrcPort, g.SrcPort),
		gtpEncoder.Int32(fieldDstPort, g.DstPort),
		gtpEncoder.Int32(fieldVersion, g.Version),
		gtpEncoder.Bool(g.ProtocolType),
		gtpEncoder.Int32(fieldGTPMessageType, g.MessageType),
		gtpEncoder.String(fieldGTPMessageTypeName, g.MessageTypeName),
		gtpEncoder.Int32(fieldLength, g.Length),
		gtpEncoder.Uint32(fieldGTPTEID, g.TEID),
		gtpEncoder.Int32(fieldGTPSequenceNumber, g.SequenceNumber),
		gtpEncoder.Bool(g.IsSignaling),
		gtpEncoder.String(fieldGTPIMSI, g.IMSI),
		gtpEncoder.String(fieldGTPMSISDN, g.MSISDN),
		gtpEncoder.String(fieldGTPIMEI, g.IMEI),
		gtpEncoder.String(fieldGTPAPNName, g.APNName),
		gtpEncoder.String(fieldGTPPDNType, g.PDNType),
		gtpEncoder.String(fieldGTPPDNAddress, g.PDNAddress),
		gtpEncoder.String(fieldGTPSGWAddress, g.SGWAddress),
		gtpEncoder.String(fieldGTPPGWAddress, g.PGWAddress),
		gtpEncoder.Int32(fieldGTPEBI, g.EBI),
		gtpEncoder.Int32(fieldGTPQCI, g.QCI),
		gtpEncoder.String(fieldGTPTAI, g.TAI),
		gtpEncoder.String(fieldGTPECGI, g.ECGI),
		gtpEncoder.Int32(fieldGTPCause, g.Cause),
		gtpEncoder.String(fieldGTPCauseName, g.CauseName),
		gtpEncoder.Bool(g.RequestAccepted),
		gtpEncoder.Bool(g.IsCreateSession),
		gtpEncoder.Bool(g.IsDeleteSession),
		gtpEncoder.Bool(g.IsModifyBearer),
		gtpEncoder.Bool(g.IsHandover),
		gtpEncoder.String(fieldGTPSecurityContext, g.SecurityContext),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (g *GTP) Analyze() {}

// NetcapType returns the type of the current audit record
func (g *GTP) NetcapType() Type {
	return Type_NC_GTP
}
