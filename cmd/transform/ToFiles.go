package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func ToFiles() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {
			if file.Context.SrcIP == ipaddr {
				if file.Name != "" {
					escapedName := maltego.EscapeText(file.Name)
					ent := trx.AddEntity("maltego.File", escapedName)
					ent.SetType("maltego.File")
					ent.SetValue(escapedName + "\n" + file.ContentType)

					di := "<h3>File</h3><p>Timestamp: " + file.Timestamp + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.Context.SrcIP + "</p><p>DstIP: " + file.Context.DstIP + "</p><p>SrcPort: " + file.Context.SrcPort + "</p><p>DstPort: " + file.Context.DstPort + "</p><p>Location: " + file.Location + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					ent.AddProperty("path", "Path", "strict", file.Location)

					//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
					ent.SetLinkColor("#000000")
					//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
				}
			}
		},
	)
}
