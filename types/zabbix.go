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
	fieldDataLength = "DataLength"
)

var fieldsZabbix = []string{
	fieldTimestamp,
	fieldRequestType, // string
	fieldHost,        // string
	fieldKey,         // string
	fieldValue,       // string
	fieldDataLength,  // int32
	fieldFlow,
	fieldSrcIP,
	fieldDstIP,
	fieldSrcPort,
	fieldDstPort,
}

// CSVHeader returns the CSV header for the audit record.
func (a *Zabbix) CSVHeader() []string {
	return filter(fieldsZabbix)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Zabbix) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.RequestType,              // string
		a.Host,                     // string
		a.Key,                      // string
		a.Value,                    // string
		formatInt32(a.DataLength),  // int32
		a.Flow,
		a.SrcIP,
		a.DstIP,
		formatInt32(a.SrcPort),
		formatInt32(a.DstPort),
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Zabbix) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Zabbix) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var zabbixMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Zabbix.String()),
		Help: Type_NC_Zabbix.String() + " audit records",
	},
	fieldsZabbix[1:],
)

// Inc increments the metrics for the audit record.
func (a *Zabbix) Inc() {
	zabbixMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Zabbix) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *Zabbix) Src() string {
	return a.SrcIP
}

// Dst returns the destination address of the audit record.
func (a *Zabbix) Dst() string {
	return a.DstIP
}

var zabbixEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Zabbix) Encode() []string {
	return filter([]string{
		zabbixEncoder.Int64(fieldTimestamp, a.Timestamp),
		zabbixEncoder.String(fieldRequestType, a.RequestType), // string
		zabbixEncoder.String(fieldHost, a.Host),               // string
		zabbixEncoder.String(fieldKey, a.Key),                 // string
		zabbixEncoder.String(fieldValue, a.Value),             // string
		zabbixEncoder.Int32(fieldDataLength, a.DataLength),    // int32
		zabbixEncoder.String(fieldFlow, a.Flow),
		zabbixEncoder.String(fieldSrcIP, a.SrcIP),
		zabbixEncoder.String(fieldDstIP, a.DstIP),
		zabbixEncoder.Int32(fieldSrcPort, a.SrcPort),
		zabbixEncoder.Int32(fieldDstPort, a.DstPort),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Zabbix) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *Zabbix) NetcapType() Type {
	return Type_NC_Zabbix
}
