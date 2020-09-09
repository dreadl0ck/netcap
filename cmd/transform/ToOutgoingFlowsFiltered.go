package transform

import (
	"fmt"
	"os"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toOutgoingFlowsFiltered() {
	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitLocalDNS()
	resolvers.InitDNSWhitelist()
	os.Stdout = stdOut

	maltego.FlowTransform(
		maltego.CountOutgoingFlowBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, flow *types.Flow, min, max uint64, path string, mac string, ipaddr string, top12 *[]int) {
			if flow.SrcIP == ipaddr {
				name := resolvers.LookupDNSNameLocal(flow.DstIP)
				if name != "" {
					if !resolvers.IsWhitelistedDomain(name) {
						if isInTop12(flow.TotalSize, top12) {
							addOutFlow(trx, flow, min, max, name, path)
						}
					}
				} else {
					if isInTop12(flow.TotalSize, top12) {
						addOutFlow(trx, flow, min, max, flow.DstIP, path)
					}
				}
			}
		},
	)
}

func addOutFlow(trx *maltego.Transform, flow *types.Flow, min, max uint64, name string, path string) {
	ent := trx.AddEntityWithPath("netcap.Flow", flow.UID+"\n"+name, path)

	di := "<h3>Outgoing Flow: " + flow.SrcIP + ":" + flow.SrcPort + " -> " + flow.DstIP + ":" + flow.DstPort + "</h3><p>Timestamp: " + utils.UnixTimeToUTC(flow.TimestampFirst) + "</p><p>TimestampLast: " + utils.UnixTimeToUTC(flow.TimestampLast) + "</p><p>Duration: " + fmt.Sprint(time.Duration(flow.Duration)) + "</p><p>TotalSize: " + humanize.Bytes(uint64(flow.TotalSize)) + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkLabel(humanize.Bytes(uint64(flow.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(flow.TotalSize), min, max))
}
