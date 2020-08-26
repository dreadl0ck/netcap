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
	"time"
)

var fieldsDeviceProfile = []string{
	"Timestamp",
	"MacAddr",
	"DeviceManufacturer",
	"NumDeviceIPs",
	"NumContacts",
	"NumPackets",
	"Bytes",
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
