package transform

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSourceDevices() {
	var ip string

	maltego.DeviceProfileTransform(maltego.CountPacketsDevices, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string) {
		if ip == "" {
			ip = strings.TrimSpace(lt.Values[maltego.PropertyIpAddr])
			if ip == "" {
				die("ipaddr not set", fmt.Sprint(lt.Values))
			}
		}

		for _, addr := range profile.DeviceIPs {
			if addr == ip {
				ident := profile.MacAddr + "\n" + profile.DeviceManufacturer
				ent := trx.AddEntityWithPath("netcap.Device", ident, path)

				ent.AddProperty("mac", "Mac Address", maltego.Strict, profile.MacAddr)
				ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
				ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
			}
		}
	})

	log.Println("done")
}
