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
	"time"

	"github.com/dreadl0ck/netcap/encoder"
)

const (
	fieldAddr                   = "Addr"
	fieldGeolocation            = "Geolocation"
	fieldDNSNames               = "DNSNames"
	fieldApplications           = "Applications"
	fieldProtocols        = "Protocols"
	fieldDstPorts         = "DstPorts"
	fieldSrcPorts         = "SrcPorts"
	fieldSNIs             = "SNIs"
	fieldJa4Fingerprints  = "Ja4Fingerprints"
	fieldJa4SFingerprints = "Ja4SFingerprints"
)

var fieldsIPProfile = []string{
	fieldAddr,           // string
	fieldNumPackets,     // int64
	fieldGeolocation,    // string
	fieldDNSNames,       // []string
	fieldTimestampFirst, // int64
	fieldTimestampLast,  // int64
	fieldApplications,   // []string
	//fieldProtocols,            // map[string]*Protocol
	fieldBytes, // uint64
	//fieldDstPorts,             // map[string]*Port
	//fieldSrcPorts,             // map[string]*Port
	//fieldSNIs,                 // map[string]int64
	fieldJa4Fingerprints,  // []string
	fieldJa4SFingerprints, // []string
}

// CSVHeader returns the CSV header for the audit record.
func (d *IPProfile) CSVHeader() []string {
	return filter(fieldsIPProfile)
}

// CSVRecord returns the CSV record for the audit record.
func (d *IPProfile) CSVRecord() []string {
	return filter([]string{
		d.Addr,
		formatInt64(d.NumPackets),
		d.Geolocation,
		join(d.DNSNames...),
		formatInt64(d.TimestampFirst),
		formatInt64(d.TimestampLast),
		join(d.Applications...),
		// d.Protocols,
		formatUint64(d.Bytes),
		// d.DstPorts,
		// d.SrcPorts,
		// d.SNIs,
		join(d.Ja4Fingerprints...),
		join(d.Ja4SFingerprints...),
	})
}

// Time returns the timestamp associated with the audit record.
func (d *IPProfile) Time() int64 {
	return d.TimestampFirst
}

// JSON returns the JSON representation of the audit record.
func (d *IPProfile) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.TimestampFirst /= int64(time.Millisecond)
	d.TimestampLast /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

// Inc increments the metrics for the audit record.
func (d *IPProfile) Inc() {}

// SetPacketContext sets the associated packet context for the audit record.
func (d *IPProfile) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (d *IPProfile) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (d *IPProfile) Dst() string {
	return ""
}

var ipProfileEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *IPProfile) Encode() []string {
	return filter([]string{
		ipProfileEncoder.String(fieldAddr, d.Addr),
		ipProfileEncoder.Int64(fieldNumPackets, d.NumPackets),
		ipProfileEncoder.String(fieldGeolocation, d.Geolocation),
		ipProfileEncoder.String(fieldDNSNames, join(d.DNSNames...)),
		ipProfileEncoder.Int64(fieldTimestampFirst, d.TimestampFirst),
		ipProfileEncoder.Int64(fieldTimestampLast, d.TimestampLast),
		ipProfileEncoder.String(fieldApplications, join(d.Applications...)),
		ipProfileEncoder.Uint64(fieldBytes, d.Bytes),
		ipProfileEncoder.String(fieldJa4Fingerprints, join(d.Ja4Fingerprints...)),
		ipProfileEncoder.String(fieldJa4SFingerprints, join(d.Ja4SFingerprints...)),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *IPProfile) Analyze() {}

// NetcapType returns the type of the current audit record
func (d *IPProfile) NetcapType() Type {
	return Type_NC_IPProfile
}
