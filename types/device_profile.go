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
	"time"

	"github.com/dreadl0ck/netcap/encoder"
)

const (
	fieldMacAddr            = "MacAddr"
	fieldDeviceManufacturer = "DeviceManufacturer"
	fieldNumDeviceIPs       = "NumDeviceIPs"
	fieldNumContacts        = "NumContacts"
	fieldBytes              = "Bytes"
)

var fieldsDeviceProfile = []string{
	fieldTimestamp,
	fieldMacAddr,
	fieldDeviceManufacturer,
	fieldNumDeviceIPs,
	fieldNumContacts,
	fieldNumPackets,
	fieldBytes,
	fieldApplications,
}

// CSVHeader returns the CSV header for the audit record.
func (d *DeviceProfile) CSVHeader() []string {
	return filter(fieldsDeviceProfile)
}

// CSVRecord returns the CSV record for the audit record.
func (d *DeviceProfile) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		d.MacAddr,
		d.DeviceManufacturer,
		strconv.Itoa(len(d.DeviceIPs)),
		strconv.Itoa(len(d.Contacts)),
		formatInt64(d.NumPackets),
		formatUint64(d.Bytes),
		join(d.Applications...),
	})
}

// Time returns the timestamp associated with the audit record.
func (d *DeviceProfile) Time() int64 {
	return d.Timestamp
}

// JSON returns the JSON representation of the audit record.
func (d *DeviceProfile) JSON() (string, error) {
	// convert unix timestamp from nano to millisecond precision for elastic
	d.Timestamp /= int64(time.Millisecond)

	return jsonMarshaler.MarshalToString(d)
}

// Inc increments the metrics for the audit record.
func (d *DeviceProfile) Inc() {}

// SetPacketContext sets the associated packet context for the audit record.
func (d *DeviceProfile) SetPacketContext(*PacketContext) {}

// Src returns the source address of the audit record.
func (d *DeviceProfile) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (d *DeviceProfile) Dst() string {
	return ""
}

var deviceProfileEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (d *DeviceProfile) Encode() []string {
	return filter([]string{
		deviceProfileEncoder.Int64(fieldTimestamp, d.Timestamp),
		deviceProfileEncoder.String(fieldMacAddr, d.MacAddr),
		deviceProfileEncoder.String(fieldDeviceManufacturer, d.DeviceManufacturer),
		deviceProfileEncoder.Int(fieldNumDeviceIPs, len(d.DeviceIPs)),
		deviceProfileEncoder.Int(fieldNumContacts, len(d.Contacts)),
		deviceProfileEncoder.Int64(fieldNumPackets, d.NumPackets),
		deviceProfileEncoder.Uint64(fieldBytes, d.Bytes),
		deviceProfileEncoder.String(fieldApplications, join(d.Applications...)),
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (d *DeviceProfile) Analyze() {
}

// NetcapType returns the type of the current audit record
func (d *DeviceProfile) NetcapType() Type {
	return Type_NC_DeviceProfile
}
