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
	fieldTag               = "Tag"
	fieldArguments         = "Arguments"
	fieldResponseText      = "ResponseText"
	fieldAuthMethod        = "AuthMethod"
	fieldMailbox           = "Mailbox"
	fieldMessageCount      = "MessageCount"
	fieldRecentCount       = "RecentCount"
	fieldUIDNext           = "UIDNext"
	fieldUIDValidity       = "UIDValidity"
	fieldSTARTTLSRequested = "STARTTLSRequested"
	fieldSTARTTLSSuccess   = "STARTTLSSuccess"
	fieldIMAPUsername      = "Username"
)

var fieldsIMAP = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldIsResponse,
	fieldTag,
	fieldCommand,
	fieldArguments,
	fieldResponse,
	fieldResponseText,
	fieldIMAPUsername,
	fieldAuthMethod,
	fieldMailbox,
	fieldMessageCount,
	fieldRecentCount,
	fieldUIDNext,
	fieldUIDValidity,
	fieldMessageID,
	fieldUID,
	fieldFlags,
	fieldSTARTTLSRequested,
	fieldSTARTTLSSuccess,
}

// CSVHeader returns the CSV header for the audit record.
func (m *IMAP) CSVHeader() []string {
	return filter(fieldsIMAP)
}

// CSVRecord returns the CSV record for the audit record.
func (m *IMAP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(m.Timestamp),
		m.SrcIP,
		m.DstIP,
		formatInt32(m.SrcPort),
		formatInt32(m.DstPort),
		strconv.FormatBool(m.IsResponse),
		m.Tag,
		m.Command,
		join(m.Arguments...),
		m.Response,
		m.ResponseText,
		m.Username,
		m.AuthMethod,
		m.Mailbox,
		formatInt32(m.MessageCount),
		formatInt32(m.RecentCount),
		formatInt32(m.UIDNext),
		formatInt32(m.UIDValidity),
		formatInt32(m.MessageID),
		formatInt32(m.UID),
		join(m.Flags...),
		strconv.FormatBool(m.STARTTLSRequested),
		strconv.FormatBool(m.STARTTLSSuccess),
	})
}

// Time returns the timestamp associated with the audit record.
func (m *IMAP) Time() int64 {
	return m.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (m *IMAP) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	m.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(m)
}

var imapMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_IMAP.String()),
		Help: Type_NC_IMAP.String() + " audit records",
	},
	fieldsIMAP[1:],
)

// Inc increments the metrics for the audit record.
func (m *IMAP) Inc() {
	imapMetric.WithLabelValues(m.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (m *IMAP) SetPacketContext(ctx *PacketContext) {
	m.SrcIP = ctx.SrcIP
	m.DstIP = ctx.DstIP
	m.SrcPort = ctx.SrcPort
	m.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (m *IMAP) Src() string {
	return m.SrcIP
}

// Dst returns the destination address of the audit record.
func (m *IMAP) Dst() string {
	return m.DstIP
}

var imapEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (m *IMAP) Encode() []string {
	return filter([]string{
		imapEncoder.Int64(fieldTimestamp, m.Timestamp),
		imapEncoder.String(fieldSrcIP, m.SrcIP),
		imapEncoder.String(fieldDstIP, m.DstIP),
		imapEncoder.Int32(fieldSrcPort, m.SrcPort),
		imapEncoder.Int32(fieldDstPort, m.DstPort),
		imapEncoder.Bool(m.IsResponse),
		imapEncoder.String(fieldTag, m.Tag),
		imapEncoder.String(fieldCommand, m.Command),
		imapEncoder.String(fieldArguments, join(m.Arguments...)),
		imapEncoder.String(fieldResponse, m.Response),
		imapEncoder.String(fieldResponseText, m.ResponseText),
		imapEncoder.String(fieldIMAPUsername, m.Username),
		imapEncoder.String(fieldAuthMethod, m.AuthMethod),
		imapEncoder.String(fieldMailbox, m.Mailbox),
		imapEncoder.Int32(fieldMessageCount, m.MessageCount),
		imapEncoder.Int32(fieldRecentCount, m.RecentCount),
		imapEncoder.Int32(fieldUIDNext, m.UIDNext),
		imapEncoder.Int32(fieldUIDValidity, m.UIDValidity),
		imapEncoder.Int32(fieldMessageID, m.MessageID),
		imapEncoder.Int32(fieldUID, m.UID),
		imapEncoder.String(fieldFlags, join(m.Flags...)),
		imapEncoder.Bool(m.STARTTLSRequested),
		imapEncoder.Bool(m.STARTTLSSuccess),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (m *IMAP) Analyze() {
}

// NetcapType returns the type of the current audit record
func (m *IMAP) NetcapType() Type {
	return Type_NC_IMAP
}
