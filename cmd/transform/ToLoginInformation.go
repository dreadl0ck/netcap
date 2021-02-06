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
	"github.com/dreadl0ck/maltego"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toLoginInformation() {
	netmaltego.CredentialsTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, cred *types.Credentials, min, max uint64, path string, mac string, ipaddr string) {
			val := cred.User + "\n" + cred.Password + "\n" + cred.Service
			if len(cred.Notes) > 0 {
				val += "\n" + cred.Notes
			}

			ent := addEntityWithPath(trx, "netcap.Credentials", val, path)
			ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(cred.Timestamp))
			ent.AddProperty("service", "Service", maltego.Strict, cred.Service)
			ent.AddProperty("flow", "Flow", maltego.Strict, cred.Flow)
			ent.AddProperty("notes", "Notes", maltego.Strict, cred.Notes)
			ent.AddProperty("user", "User", maltego.Strict, cred.User)
			ent.AddProperty("password", "Password", maltego.Strict, cred.Password)
		},
	)
}
