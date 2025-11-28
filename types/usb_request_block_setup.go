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
	fieldRequestType = "RequestType"
	fieldValue       = "Value"
	fieldIndex       = "Index"
)

var fieldsUSBRequestBlockSetup = []string{
	fieldTimestamp,
	fieldRequestType, // int32
	fieldRequest,     // int32
	fieldValue,       // int32
	fieldIndex,       // int32
	fieldLength,      // int32
}

// CSVHeader returns the CSV header for the audit record.
func (a *USBRequestBlockSetup) CSVHeader() []string {
	return filter(fieldsUSBRequestBlockSetup)
}

// CSVRecord returns the CSV record for the audit record.
func (a *USBRequestBlockSetup) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.RequestType), // int32
		formatInt32(a.Request),     // int32
		formatInt32(a.Value),       // int32
		formatInt32(a.Index),       // int32
		formatInt32(a.Length),      // int32
	})
}

// Time returns the timestamp associated with the audit record.
func (a *USBRequestBlockSetup) Time() int64 {
	return a.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (a *USBRequestBlockSetup) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(a)
}

var usbRequestBlockSetupMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_USBRequestBlockSetup.String()),
		Help: Type_NC_USBRequestBlockSetup.String() + " audit records",
	},
	fieldsUSBRequestBlockSetup[1:],
)

// Inc increments the metrics for the audit record.
func (a *USBRequestBlockSetup) Inc() {
	usbRequestBlockSetupMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *USBRequestBlockSetup) SetPacketContext(*PacketContext) {}

// Src TODO return source DeviceAddress?
// Src returns the source address of the audit record.
func (a *USBRequestBlockSetup) Src() string {
	return ""
}

// Dst TODO return destination DeviceAddress?
// Dst returns the destination address of the audit record.
func (a *USBRequestBlockSetup) Dst() string {
	return ""
}

var usbRequestBlockSetupEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *USBRequestBlockSetup) Encode() []string {
	return filter([]string{
		usbRequestBlockSetupEncoder.Int64(fieldTimestamp, a.Timestamp),
		usbRequestBlockSetupEncoder.Int32(fieldRequestType, a.RequestType), // int32
		usbRequestBlockSetupEncoder.Int32(fieldRequest, a.Request),         // int32
		usbRequestBlockSetupEncoder.Int32(fieldValue, a.Value),             // int32
		usbRequestBlockSetupEncoder.Int32(fieldIndex, a.Index),             // int32
		usbRequestBlockSetupEncoder.Int32(fieldLength, a.Length),           // int32
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *USBRequestBlockSetup) Analyze() {
}

// NetcapType returns the type of the current audit record
func (a *USBRequestBlockSetup) NetcapType() Type {
	return Type_NC_USBRequestBlockSetup
}
