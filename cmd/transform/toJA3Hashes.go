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

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toJA3Hashes() {
	netmaltego.TLSClientHelloTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, hello *types.TLSClientHello, min, max uint64, path string, ipaddr string) {
			ent := addEntityWithPath(trx, "netcap.TLSClientHello", hello.Ja3, path)
			ent.AddProperty("ip", "IP", maltego.Strict, hello.SrcIP)
			ent.AddProperty("port", "Port", maltego.Strict, strconv.Itoa(int(hello.SrcPort)))
			ent.AddDisplayInformation(utils.CreateFlowIdent(hello.SrcIP, strconv.Itoa(int(hello.SrcPort)), hello.DstIP, strconv.Itoa(int(hello.DstPort)))+"<br>", "Flows")
		},
	)
}
