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
	fieldMITRE          = "MITRE"          // string
	fieldIPReputation   = "IPReputation"   // string
	fieldRuleName       = "RuleName"       // string
	fieldRecordType     = "RecordType"     // string
	fieldAlertSeverity  = "Severity"       // string (renamed to avoid conflict with vulnerability.go)
	fieldTags           = "Tags"           // string
	fieldMatchedRecord  = "MatchedRecord"  // string
	fieldRuleExpression = "RuleExpression" // string
)

var fieldsAlert = []string{
	fieldTimestamp,
	fieldName,
	fieldDescription,
	fieldSrcIP,
	fieldSrcPort,
	fieldDstIP,
	fieldDstPort,
	fieldMITRE,
	fieldIPReputation,
	fieldRuleName,
	fieldRecordType,
	fieldAlertSeverity,
	fieldTags,
	fieldMatchedRecord,
	fieldRuleExpression,
}

// CSVHeader returns the CSV header for the audit record.
func (a *Alert) CSVHeader() []string {
	return filter(fieldsAlert)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Alert) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Name,
		a.Description,
		a.SrcIP,
		a.SrcPort,
		a.DstIP,
		a.DstPort,
		a.MITRE,
		a.IPReputation,
		a.RuleName,
		a.RecordType,
		a.Severity,
		strings.Join(a.Tags, ","),
		a.MatchedRecord,
		a.RuleExpression,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Alert) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Alert) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var aMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Alert.String()),
		Help: Type_NC_Alert.String() + " audit records",
	},
	fieldsAlert[1:],
)

// Inc increments the metrics for the audit record.
func (a *Alert) Inc() {
	aMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Alert) SetPacketContext(*PacketContext) {}

// Src TODO: preserve source and destination mac adresses for Alert and return them here.
// Src returns the source address of the audit record.
func (a *Alert) Src() string {
	return ""
}

// Dst TODO: preserve source and destination mac adresses for Alert and return them here.
// Dst returns the destination address of the audit record.
func (a *Alert) Dst() string {
	return ""
}

var aEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Alert) Encode() []string {
	return filter([]string{
		aEncoder.Int64(fieldTimestamp, a.Timestamp), // int64
		aEncoder.String(fieldName, a.Name),
		aEncoder.String(fieldDescription, a.Description),
		aEncoder.String(fieldSrcIP, a.SrcIP),
		aEncoder.String(fieldSrcPort, a.SrcPort),
		aEncoder.String(fieldDstIP, a.DstIP),
		aEncoder.String(fieldDstPort, a.DstPort),
		aEncoder.String(fieldMITRE, a.MITRE),
		aEncoder.String(fieldIPReputation, a.IPReputation),
		aEncoder.String(fieldRuleName, a.RuleName),
		aEncoder.String(fieldRecordType, a.RecordType),
		aEncoder.String(fieldAlertSeverity, a.Severity),
		aEncoder.String(fieldTags, strings.Join(a.Tags, ",")),
		aEncoder.String(fieldMatchedRecord, a.MatchedRecord),
		aEncoder.String(fieldRuleExpression, a.RuleExpression),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Alert) Analyze() {}

// NetcapType returns the type of the current audit record
func (a *Alert) NetcapType() Type {
	return Type_NC_Alert
}
