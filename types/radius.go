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

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/prometheus/client_golang/prometheus"
)

// RADIUS-specific field constants
const (
	fieldRADIUSCode             = "Code"
	fieldRADIUSCodeName         = "CodeName"
	fieldRADIUSIdentifier       = "Identifier"
	fieldRADIUSNASIPAddress     = "NASIPAddress"
	fieldRADIUSNASIdentifier    = "NASIdentifier"
	fieldRADIUSNASPort          = "NASPort"
	fieldRADIUSNASPortType      = "NASPortType"
	fieldRADIUSCalledStationID  = "CalledStationID"
	fieldRADIUSCallingStationID = "CallingStationID"
	fieldRADIUSServiceType      = "ServiceType"
	fieldRADIUSServiceTypeName  = "ServiceTypeName"
	fieldRADIUSFramedProtocol   = "FramedProtocol"
	fieldRADIUSFramedIPAddress  = "FramedIPAddress"
	fieldRADIUSAcctSessionID    = "AcctSessionID"
	fieldRADIUSAcctStatusType   = "AcctStatusType"
	fieldRADIUSReplyMessage     = "ReplyMessage"
	fieldRADIUSIsRequest        = "IsRequest"
	fieldRADIUSAuthSuccess      = "AuthSuccess"
)

var fieldsRADIUS = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldRADIUSCode,
	fieldRADIUSCodeName,
	fieldRADIUSIdentifier,
	fieldUsername,
	fieldRADIUSNASIPAddress,
	fieldRADIUSNASIdentifier,
	fieldRADIUSServiceType,
	fieldRADIUSServiceTypeName,
	fieldRADIUSAcctSessionID,
	fieldRADIUSAcctStatusType,
	fieldRADIUSReplyMessage,
	fieldRADIUSIsRequest,
	fieldRADIUSAuthSuccess,
}

// CSVHeader returns the CSV header for the audit record.
func (r *RADIUS) CSVHeader() []string {
	return filter(fieldsRADIUS)
}

// CSVRecord returns the CSV record for the audit record.
func (r *RADIUS) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(r.Timestamp),
		r.SrcIP,
		r.DstIP,
		formatInt32(r.SrcPort),
		formatInt32(r.DstPort),
		formatInt32(r.Code),
		r.CodeName,
		formatInt32(r.Identifier),
		r.Username,
		r.NASIPAddress,
		r.NASIdentifier,
		formatInt32(r.ServiceType),
		r.ServiceTypeName,
		r.AcctSessionID,
		formatInt32(r.AcctStatusType),
		r.ReplyMessage,
		strconv.FormatBool(r.IsRequest),
		strconv.FormatBool(r.AuthSuccess),
	})
}

// Time returns the timestamp associated with the audit record.
func (r *RADIUS) Time() int64 {
	return r.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (r *RADIUS) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	r.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(r)
}

var radiusMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_RADIUS.String()),
		Help: Type_NC_RADIUS.String() + " audit records",
	},
	fieldsRADIUS[1:],
)

// Inc increments the metrics for the audit record.
func (r *RADIUS) Inc() {
	radiusMetric.WithLabelValues(r.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (r *RADIUS) SetPacketContext(ctx *PacketContext) {
	r.SrcIP = ctx.SrcIP
	r.DstIP = ctx.DstIP
	r.SrcPort = ctx.SrcPort
	r.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (r *RADIUS) Src() string {
	return r.SrcIP
}

// Dst returns the destination address of the audit record.
func (r *RADIUS) Dst() string {
	return r.DstIP
}

var radiusEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (r *RADIUS) Encode() []string {
	return filter([]string{
		radiusEncoder.Int64(fieldTimestamp, r.Timestamp),
		radiusEncoder.String(fieldSrcIP, r.SrcIP),
		radiusEncoder.String(fieldDstIP, r.DstIP),
		radiusEncoder.Int32(fieldSrcPort, r.SrcPort),
		radiusEncoder.Int32(fieldDstPort, r.DstPort),
		radiusEncoder.Int32(fieldRADIUSCode, r.Code),
		radiusEncoder.String(fieldRADIUSCodeName, r.CodeName),
		radiusEncoder.Int32(fieldRADIUSIdentifier, r.Identifier),
		radiusEncoder.String(fieldUsername, r.Username),
		radiusEncoder.String(fieldRADIUSNASIPAddress, r.NASIPAddress),
		radiusEncoder.String(fieldRADIUSNASIdentifier, r.NASIdentifier),
		radiusEncoder.Int32(fieldRADIUSServiceType, r.ServiceType),
		radiusEncoder.String(fieldRADIUSServiceTypeName, r.ServiceTypeName),
		radiusEncoder.String(fieldRADIUSAcctSessionID, r.AcctSessionID),
		radiusEncoder.Int32(fieldRADIUSAcctStatusType, r.AcctStatusType),
		radiusEncoder.String(fieldRADIUSReplyMessage, r.ReplyMessage),
		radiusEncoder.Bool(r.IsRequest),
		radiusEncoder.Bool(r.AuthSuccess),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (r *RADIUS) Analyze() {}

// NetcapType returns the type of the current audit record
func (r *RADIUS) NetcapType() Type {
	return Type_NC_RADIUS
}
