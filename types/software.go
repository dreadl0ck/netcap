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
	fieldDeviceProfiles = "DeviceProfiles"
	fieldSourceName     = "SourceName"
	fieldDPIResults     = "DPIResults"
	fieldFlows          = "Flows"
	fieldSourceData     = "SourceData"
)

var fieldsSoftware = []string{
	fieldTimestamp,
	fieldProduct,
	fieldVendor,
	fieldVersion,
	fieldDeviceProfiles,
	fieldSourceName,
	fieldDPIResults,
	fieldService,
	fieldFlows,
	fieldSourceData,
	fieldNotes,
}

// CSVHeader returns the CSV header for the audit record.
func (a *Software) CSVHeader() []string {
	return filter(fieldsSoftware)
}

// CSVRecord returns the CSV record for the audit record.
func (a *Software) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Product,
		a.Vendor,
		a.Version,
		join(a.DeviceProfiles...),
		a.SourceName,
		join(a.DPIResults...),
		a.Service,
		join(a.Flows...),
		a.SourceData,
		a.Notes,
	})
}

// Time returns the timestamp associated with the audit record.
func (a *Software) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *Software) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var fieldsSoftwareMetric = []string{
	"Product",
	"Vendor",
	"Version",
	"NumDeviceProfiles",
	"SourceName",
	//"NumDPIResults",
	"Service",
	//"Flows",
	//"SourceData",
	//"Notes",
}

var softwareMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Software.String()),
		Help: Type_NC_Software.String() + " audit records",
	},
	fieldsSoftwareMetric,
)

func (a *Software) metricValues() []string {
	return []string{
		a.Product,
		a.Vendor,
		a.Version,
		strconv.Itoa(len(a.DeviceProfiles)),
		a.SourceName,
		a.Service,
	}
}

// Inc increments the metrics for the audit record.
func (a *Software) Inc() {
	softwareMetric.WithLabelValues(a.metricValues()...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *Software) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (a *Software) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *Software) Dst() string {
	return ""
}

var softwareEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *Software) Encode() []string {
	return filter([]string{
		softwareEncoder.Int64(fieldTimestamp, a.Timestamp),
		softwareEncoder.String(fieldProduct, a.Product),
		softwareEncoder.String(fieldVendor, a.Vendor),
		softwareEncoder.String(fieldVersion, a.Version),
		softwareEncoder.String(fieldDeviceProfiles, join(a.DeviceProfiles...)),
		softwareEncoder.String(fieldSourceName, a.SourceName),
		softwareEncoder.String(fieldDPIResults, join(a.DPIResults...)),
		softwareEncoder.String(fieldService, a.Service),
		softwareEncoder.String(fieldFlows, join(a.Flows...)),
		softwareEncoder.String(fieldSourceData, a.SourceData),
		softwareEncoder.String(fieldNotes, a.Notes),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *Software) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *Software) NetcapType() Type {
	return Type_NC_Software
}
