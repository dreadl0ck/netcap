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
)

func toDNSQuestions() {
	results := make(map[string]int)

	netmaltego.DNSTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DNS, min, max uint64, path string, ipaddr string) {
			for _, q := range d.Questions {
				if len(q.Name) != 0 {

					// prevent duplicating results
					if _, exists := results[q.Name]; exists {
						continue
					}
					results[q.Name]++

					ent := addEntityWithPath(trx, "netcap.DNSName", q.Name, path)
					ent.AddProperty("srcIP", "SourceIP", maltego.Strict, d.SrcIP)
					ent.SetLinkLabel(strconv.Itoa(results[q.Name]))
				}
			}
		},
		false,
	)
}
