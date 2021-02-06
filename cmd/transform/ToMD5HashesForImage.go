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

func toMD5HashesForImage() {
	var (
		name   string
		length int64
	)

	netmaltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, path string, ipaddr string) {
			if len(name) == 0 {
				name = lt.Values["name"]
				var errLength error
				length, errLength = strconv.ParseInt(lt.Values["length"], 10, 64)
				if errLength != nil {
					log.Fatal("invalid length value: ", lt.Values["length"])
				}
				log.Println(lt.Values)
			}

			if file.Name == name && file.Length == length {
				var (
					ent = addEntityWithPath(trx, "netcap.MD5Hash", file.Hash, path)
					di  = "<h3>File</h3><p>Timestamp: " + utils.UnixTimeToUTC(file.Timestamp) + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.SrcIP + "</p><p>DstIP: " + file.DstIP + "</p><p>SrcPort: " + strconv.FormatInt(int64(file.SrcPort), 10) + "</p><p>DstPort: " + strconv.FormatInt(int64(file.DstPort), 10) + "</p><p>Location: " + file.Location + "</p>"
				)
				ent.AddDisplayInformation(di, "Netcap Info")

			}
		},
	)
}
