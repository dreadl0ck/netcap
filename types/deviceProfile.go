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

import "strconv"

var fieldsDeviceProfile = []string{
	"Timestamp",
	"MacAddr",
	"DeviceManufacturer",
	"NumDeviceIPs",
	"NumContacts",
	"NumPackets",
	"Bytes",
}

func (d *DeviceProfile) CSVHeader() []string {
	return filter(fieldsDeviceProfile)
}

func (d *DeviceProfile) CSVRecord() []string {
	return filter([]string{
		d.Timestamp,
		d.MacAddr,
		d.DeviceManufacturer,
		strconv.Itoa(len(d.DeviceIPs)),
		strconv.Itoa(len(d.Contacts)),
		formatInt64(d.NumPackets),
		formatUint64(d.Bytes),
	})
}

func (d *DeviceProfile) Time() string {
	return ""
}

func (d *DeviceProfile) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(d)
}

func (d *DeviceProfile) Inc() {}

func (d *DeviceProfile) SetPacketContext(*PacketContext) {}

func (d *DeviceProfile) Src() string {
	return ""
}

func (d *DeviceProfile) Dst() string {
	return ""
}
