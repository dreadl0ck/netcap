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

package transform

import (
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"strconv"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDevices() {
	netmaltego.DeviceProfileTransform(netmaltego.CountPacketsDevices, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string) {
		ident := profile.MacAddr + "\n" + profile.DeviceManufacturer
		ent := addEntityWithPath(trx, "netcap.Device", ident, path)

		ent.AddProperty("mac", "Mac Address", maltego.Strict, profile.MacAddr)

		ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
		ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
	})
}
