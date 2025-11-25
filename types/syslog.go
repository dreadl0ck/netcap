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

// Syslog-specific field constants
const (
	fieldSyslogPriority           = "Priority"
	fieldSyslogFacility           = "Facility"
	fieldSyslogFacilityName       = "FacilityName"
	fieldSyslogSeverity           = "Severity"
	fieldSyslogSeverityName       = "SeverityName"
	fieldSyslogHostname           = "Hostname"
	fieldSyslogTag                = "Tag"
	fieldSyslogProcessID          = "ProcessID"
	fieldSyslogMessage            = "Message"
	fieldSyslogAppName            = "AppName"
	fieldSyslogMsgID              = "MsgID"
	fieldSyslogIsSecurityRelevant = "IsSecurityRelevant"
)

var fieldsSyslog = []string{
	fieldTimestamp,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
	fieldSyslogPriority,
	fieldSyslogFacility,
	fieldSyslogFacilityName,
	fieldSyslogSeverity,
	fieldSyslogSeverityName,
	fieldSyslogHostname,
	fieldSyslogTag,
	fieldSyslogProcessID,
	fieldSyslogMessage,
	fieldSyslogAppName,
	fieldSyslogMsgID,
	fieldSyslogIsSecurityRelevant,
}

// CSVHeader returns the CSV header for the audit record.
func (s *Syslog) CSVHeader() []string {
	return filter(fieldsSyslog)
}

// CSVRecord returns the CSV record for the audit record.
func (s *Syslog) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		s.SrcIP,
		s.DstIP,
		formatInt32(s.SrcPort),
		formatInt32(s.DstPort),
		formatInt32(s.Priority),
		formatInt32(s.Facility),
		s.FacilityName,
		formatInt32(s.Severity),
		s.SeverityName,
		s.Hostname,
		s.Tag,
		formatInt32(s.ProcessID),
		s.Message,
		s.AppName,
		s.MsgID,
		strconv.FormatBool(s.IsSecurityRelevant),
	})
}

// Time returns the timestamp associated with the audit record.
func (s *Syslog) Time() int64 {
	return s.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (s *Syslog) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	s.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(s)
}

var syslogMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Syslog.String()),
		Help: Type_NC_Syslog.String() + " audit records",
	},
	fieldsSyslog[1:],
)

// Inc increments the metrics for the audit record.
func (s *Syslog) Inc() {
	syslogMetric.WithLabelValues(s.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (s *Syslog) SetPacketContext(ctx *PacketContext) {
	s.SrcIP = ctx.SrcIP
	s.DstIP = ctx.DstIP
	s.SrcPort = ctx.SrcPort
	s.DstPort = ctx.DstPort
}

// Src returns the source address of the audit record.
func (s *Syslog) Src() string {
	return s.SrcIP
}

// Dst returns the destination address of the audit record.
func (s *Syslog) Dst() string {
	return s.DstIP
}

var syslogEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (s *Syslog) Encode() []string {
	return filter([]string{
		syslogEncoder.Int64(fieldTimestamp, s.Timestamp),
		syslogEncoder.String(fieldSrcIP, s.SrcIP),
		syslogEncoder.String(fieldDstIP, s.DstIP),
		syslogEncoder.Int32(fieldSrcPort, s.SrcPort),
		syslogEncoder.Int32(fieldDstPort, s.DstPort),
		syslogEncoder.Int32(fieldSyslogPriority, s.Priority),
		syslogEncoder.Int32(fieldSyslogFacility, s.Facility),
		syslogEncoder.String(fieldSyslogFacilityName, s.FacilityName),
		syslogEncoder.Int32(fieldSyslogSeverity, s.Severity),
		syslogEncoder.String(fieldSyslogSeverityName, s.SeverityName),
		syslogEncoder.String(fieldSyslogHostname, s.Hostname),
		syslogEncoder.String(fieldSyslogTag, s.Tag),
		syslogEncoder.Int32(fieldSyslogProcessID, s.ProcessID),
		syslogEncoder.String(fieldSyslogMessage, s.Message),
		syslogEncoder.String(fieldSyslogAppName, s.AppName),
		syslogEncoder.String(fieldSyslogMsgID, s.MsgID),
		syslogEncoder.Bool(s.IsSecurityRelevant),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (s *Syslog) Analyze() {}

// NetcapType returns the type of the current audit record
func (s *Syslog) NetcapType() Type {
	return Type_NC_Syslog
}

