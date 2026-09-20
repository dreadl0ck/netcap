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
	fieldIsEncrypted = "IsEncrypted"
	fieldMailIDs     = "MailIDs"
	fieldCommands    = "Commands"
)

var fieldsSMTP = []string{
	fieldTimestamp,
	fieldIsEncrypted, // bool
	fieldIsResponse,  // bool
	fieldMailIDs,     // []string
	fieldCommands,    // []string
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *SMTP) CSVHeader() []string {
	return filter(fieldsSMTP)
}

// CSVRecord returns the CSV record for the audit record.
func (a *SMTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.IsEncrypted), // bool
		strconv.FormatBool(a.IsResponse),  // bool
		join(a.MailIDs...),
		join(a.Commands...),
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *SMTP) Time() int64 {
	return a.Timestamp
}

func (a *SMTPCommand) getString() string {
	if a == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(a.Command))
	b.WriteString(FieldSeparator)
	b.WriteString(a.Parameter)
	b.WriteString(StructureEnd)
	return b.String()
}

func (a *SMTPResponse) getString() string {
	if a == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(a.ResponseCode))
	b.WriteString(FieldSeparator)
	b.WriteString(a.Parameter)
	b.WriteString(StructureEnd)
	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (a *SMTP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var smtpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SMTP.String()),
		Help: Type_NC_SMTP.String() + " audit records",
	},
	fieldsSMTP[1:],
)

// Inc increments the metrics for the audit record.
func (a *SMTP) Inc() {
	smtpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *SMTP) SetPacketContext(ctx *PacketContext) {
	a.SrcIP = ctx.SrcIP
	a.DstIP = ctx.DstIP
	a.SrcPort = ctx.SrcPort
	a.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (a *SMTP) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *SMTP) Dst() string {
	return a.DstIP
}

var smtpEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *SMTP) Encode() []string {
	return filter([]string{
		smtpEncoder.Int64(fieldTimestamp, a.Timestamp),
		smtpEncoder.Bool(a.IsEncrypted), // bool
		smtpEncoder.Bool(a.IsResponse),  // bool
		smtpEncoder.String(fieldMailIDs, join(a.MailIDs...)),
		smtpEncoder.String(fieldCommands, join(a.Commands...)),
		smtpEncoder.String(fieldSrcIP, a.SrcIP),
		smtpEncoder.String(fieldDstIP, a.DstIP),
		smtpEncoder.Int32(fieldSrcPort, a.SrcPort),
		smtpEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *SMTP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *SMTP) NetcapType() Type {
	return Type_NC_SMTP
}
