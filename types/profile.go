/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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

var fieldsDeviceProfile = []string{
	"MacAddr",
	"DeviceManufacturer",
	"DeviceIPs",
	"Contacts",
}

func (c DeviceProfile) CSVHeader() []string {
	return filter(fieldsDeviceProfile)
}

func (c DeviceProfile) CSVRecord() []string {
	return filter([]string{})
}

func (c DeviceProfile) Time() string {
	return ""
}

func (a DeviceProfile) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

func (a DeviceProfile) Inc() {}

func (a DeviceProfile) SetPacketContext(ctx *PacketContext) {}

func (a DeviceProfile) Src() string {
	return ""
}

func (a DeviceProfile) Dst() string {
	return ""
}
