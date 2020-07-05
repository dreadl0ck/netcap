package transform

import (
	"fmt"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"os"
	"time"
)

func ToIncomingFlowsFiltered() {

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitLocalDNS()
	resolvers.InitDNSWhitelist()
	os.Stdout = stdOut

	maltego.FlowTransform(
		maltego.CountIncomingFlowBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, flow *types.Flow, min, max uint64, profilesFile string, mac string, ipaddr string, top12 *[]int) {
			if flow.DstIP == ipaddr {
				name := resolvers.LookupDNSNameLocal(flow.SrcIP)
				if name != "" {
					if !resolvers.IsWhitelistedDomain(name) {
						if isInTop12(flow.TotalSize, top12) {
							addInFlow(trx, flow, min, max, name)
						}
					}
				} else {
					if isInTop12(flow.TotalSize, top12) {
						addInFlow(trx, flow, min, max, flow.SrcIP)
					}
				}
			}
		},
	)
}

func isInTop12(val int32, sizes *[]int) bool {
	for _, s := range *sizes {
		if s == int(val) {
			return true
		}
	}
	return false
}

func addInFlow(trx *maltego.MaltegoTransform, flow *types.Flow, min, max uint64, name string) {

	ent := trx.AddEntity("netcap.Flow", flow.UID + "\n" + name)

	di := "<h3>Incoming Flow: " + flow.SrcIP + ":" + flow.SrcPort + " -> " + flow.DstIP + ":" + flow.DstPort + "</h3><p>Timestamp: " + utils.TimeToUTC(flow.TimestampFirst) + "</p><p>TimestampLast: " + utils.TimeToUTC(flow.TimestampLast) + "</p><p>Duration: " + fmt.Sprint(time.Duration(flow.Duration)) + "</p><p>TotalSize: " + humanize.Bytes(uint64(flow.TotalSize)) + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkDirection("output-to-input")
	ent.SetLinkLabel(humanize.Bytes(uint64(flow.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(flow.TotalSize), min, max))
}
