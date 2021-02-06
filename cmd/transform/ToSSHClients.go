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

func toSSHClients() {
	netmaltego.SSHTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, ssh *types.SSH, min, max uint64, path string, mac string, ipaddr string) {
			if ssh.IsClient {
				val := ssh.HASSH
				if len(ssh.Ident) > 0 {
					val += "\n" + ssh.Ident
				}

				ent := addEntityWithPath(trx, "netcap.SSHClient", val, path)
				ent.AddProperty("timestamp", "Timestamp", maltego.Strict, utils.UnixTimeToUTC(ssh.Timestamp))
				ent.AddProperty("ident", "Ident", maltego.Strict, ssh.Ident)
				ent.AddProperty("algorithms", "Algorithms", maltego.Strict, ssh.Algorithms)

				ent.AddDisplayInformation(ssh.Flow+"<br>", "Flows")
			}
		},
	)
}
