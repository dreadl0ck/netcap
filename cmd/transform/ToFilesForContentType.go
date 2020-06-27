package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"path/filepath"
	"strconv"
	"strings"
)

func ToFilesForContentType() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {
			if file.Context.SrcIP == ipaddr || file.Context.DstIP == ipaddr {

				var (
					ct  = lt.Values["properties.contenttype"]
					typ = file.ContentTypeDetected
				)

				// ignore encoding value when matching
				parts := strings.Split(file.ContentTypeDetected, ";")
				if len(parts) > 1 {
					typ = parts[0]
				}

				if typ == ct {

					var (
						escapedName = maltego.EscapeText(file.Name)
						ent         *maltego.MaltegoEntityObj
					)
					if strings.HasPrefix(ct, "image/") {
						ent = trx.AddEntity("maltego.Image", escapedName)
						ent.SetType("maltego.Image")
					} else {
						ent = trx.AddEntity("netcap.File", escapedName)
						ent.SetType("netcap.File")
					}

					ent.SetValue(escapedName + "\n" + file.ContentType)

					di := "<h3>File</h3><p>Timestamp: " + file.Timestamp + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.Context.SrcIP + "</p><p>DstIP: " + file.Context.DstIP + "</p><p>SrcPort: " + file.Context.SrcPort + "</p><p>DstPort: " + file.Context.DstPort + "</p><p>Location: " + file.Location + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					if filepath.IsAbs(file.Location) {
						ent.SetIconURL("file://" + file.Location)
					} else {
						ent.SetIconURL("file://" + filepath.Join(filepath.Join(filepath.Dir(profilesFile), ".."), file.Location))
					}
					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", file.Location)
					ent.AddProperty("location", "Location", "strict", file.Location)

					//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
				}
			}
		},
	)
}
