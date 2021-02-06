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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toFilesForContentType() {
	netmaltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, path string, ipaddr string) {
			if ipaddr == "" || file.SrcIP == ipaddr || file.DstIP == ipaddr {

				var (
					ct  = lt.Values["properties.contenttype"]
					typ = file.ContentTypeDetected
				)

				// ignore encoding value when matching
				parts := strings.Split(file.ContentTypeDetected, ";")
				if len(parts) > 1 {
					typ = parts[0]
				}

				if typ == ct { // TODO: make a single file constructor and reuse it in toFiles!

					var (
						ent *maltego.Entity
						val = file.Name + "\n" + strconv.FormatInt(file.Length, 10) + " bytes"
					)
					if strings.HasPrefix(ct, "image/") {
						ent = addEntityWithPath(trx, "maltego.Image", val, path)
					} else {
						ent = addEntityWithPath(trx, "netcap.File", val, path)
					}

					di := "<h3>File</h3><p>Timestamp: " + utils.UnixTimeToUTC(file.Timestamp) + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.SrcIP + "</p><p>DstIP: " + file.DstIP + "</p><p>SrcPort: " + strconv.FormatInt(int64(file.SrcPort), 10) + "</p><p>DstPort: " + strconv.FormatInt(int64(file.DstPort), 10) + "</p><p>Location: " + maltego.EscapeText(file.Location) + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					if filepath.IsAbs(file.Location) {
						ent.IconURL = "file://" + maltego.EscapeText(file.Location)
					} else {
						ent.IconURL = "file://" + filepath.Join(filepath.Join(filepath.Dir(path), ".."), maltego.EscapeText(file.Location))
					}
					ent.AddProperty(netmaltego.PropertyIpAddr, netmaltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)

					ent.AddProperty("location", "Location", maltego.Strict, maltego.EscapeText(file.Location))
					ent.AddProperty("name", "Name", maltego.Strict, maltego.EscapeText(file.Name))
					ent.AddProperty("length", "Length", maltego.Strict, strconv.FormatInt(file.Length, 10))
				}
			}
		},
	)
}
