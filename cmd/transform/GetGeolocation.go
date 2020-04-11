package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func GetGeolocation() {
	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile  *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {
				for _, ip := range profile.Contacts {
					if ip.Addr == ipaddr {
						if ip.Geolocation == "" {
							continue
						}
						addGeolocation(trx, ip, min, max)
					}
				}
				for _, ip := range profile.DeviceIPs {
					if ip.Addr == ipaddr {
						if ip.Geolocation == "" {
							continue
						}
						addGeolocation(trx, ip, min, max)
					}
				}
			}
		},
	)
}

func addGeolocation(trx *maltego.MaltegoTransform, ip *types.IPProfile, min, max uint64) {
	ent := trx.AddEntity("maltego.Location", ip.Geolocation)
	ent.SetType("maltego.Location")
	ent.SetValue(ip.Geolocation)

	// di := "<h3>Geolocation</h3><p>Timestamp: " + ip.TimestampFirst + "</p>"
	// ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkLabel(strconv.FormatInt(ip.NumPackets, 10) + " pkts")
	ent.SetLinkColor("#000000")
	ent.SetLinkThickness(maltego.GetThickness(uint64(ip.NumPackets), min, max))
}