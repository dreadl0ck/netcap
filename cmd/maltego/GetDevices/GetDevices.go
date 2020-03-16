package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"strconv"
)

func main() {
	maltego.DeviceProfileTransform(maltego.CountPacketsDevices, func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, minPackets, maxPackets uint64, profilesFile string, mac string) {

		ident := profile.MacAddr + "\n" + profile.DeviceManufacturer
		ent := trx.AddEntity("netcap.Device", ident)
		ent.SetType("netcap.Device")
		ent.SetValue(ident)

		di := "<h3>Device</h3><p>Ident: "+ ident +"</p><p>MacAddr: "+ profile.MacAddr +"</p><p>DeviceManufacturer: "+ profile.DeviceManufacturer +"</p><p>Timestamp: " + profile.Timestamp + "</p>"
		ent.AddDisplayInformation(di, "Netcap Info")

		ent.AddProperty("path", "Path", "strict", profilesFile)
		ent.AddProperty("mac", "Mac Address", "strict", profile.MacAddr)

		ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
		ent.SetLinkColor("#000000")
		ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), minPackets, maxPackets))
	})
}
