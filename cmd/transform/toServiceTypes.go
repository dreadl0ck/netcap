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
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toServiceTypes() {
	var (
		// ips to total bytes transferred (client + server)
		services        = make(map[string]int64)
		auditRecordPath string
	)

	netmaltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, path string, mac string, ipaddr string) {
			if auditRecordPath == "" {
				auditRecordPath = path
			}
			if service.Name != "" {
				services[service.Name] += int64(service.BytesClient + service.BytesServer)
			}
		},
		true,
	)

	trx := &maltego.Transform{}
	for service, numBytes := range services {
		ent := addEntityWithPath(trx, "netcap.ServiceType", service, auditRecordPath)
		ent.SetLinkLabel(humanize.Bytes(uint64(numBytes)))
		// TODO: num pkts / set thickness
		// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
