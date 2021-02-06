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
	"log"
	"strconv"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toApplications() {
	netmaltego.IPProfileTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.Addr == ipaddr {
				log.Println(profile.Applications)
				for app, info := range profile.Protocols {
					addApplication(app, info, trx, path, profile)
				}
			}
		},
	)
}

func addApplication(app string, info *types.Protocol, trx *maltego.Transform, path string, profile *types.IPProfile) {
	ent := addEntityWithPath(trx, "netcap.Application", app, path)

	di := "<h3>Application</h3><p>Timestamp first seen: " + utils.UnixTimeToUTC(profile.TimestampFirst) + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkLabel(strconv.FormatInt(int64(info.Packets), 10) + " pkts")
}
