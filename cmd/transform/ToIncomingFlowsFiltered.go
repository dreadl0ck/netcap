package transform

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toIncomingFlowsFiltered() {
	resolverLog := zap.New(zapcore.NewNopCore())
	defer func() {
		err := resolverLog.Sync()
		if err != nil {
			log.Println(err)
		}
	}()

	resolvers.SetLogger(resolverLog)

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitLocalDNS()
	resolvers.InitDNSWhitelist()
	os.Stdout = stdOut

	maltego.FlowTransform(
		maltego.CountIncomingFlowBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, flow *types.Flow, min, max uint64, path string, mac string, ipaddr string, top12 *[]int) {
			if flow.DstIP == ipaddr {
				name := resolvers.LookupDNSNameLocal(flow.SrcIP)
				if name != "" {
					if !resolvers.IsWhitelistedDomain(name) {
						if isInTop12(flow.TotalSize, top12) {
							addInFlow(trx, flow, min, max, name, path)
						}
					}
				} else {
					if isInTop12(flow.TotalSize, top12) {
						addInFlow(trx, flow, min, max, flow.SrcIP, path)
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

func addInFlow(trx *maltego.Transform, flow *types.Flow, min, max uint64, name string, path string) {
	ent := trx.AddEntityWithPath("netcap.Flow", flow.UID+"\n"+name, path)

	di := "<h3>Incoming Flow: " + flow.SrcIP + ":" + flow.SrcPort + " -> " + flow.DstIP + ":" + flow.DstPort + "</h3><p>Timestamp: " + utils.UnixTimeToUTC(flow.TimestampFirst) + "</p><p>TimestampLast: " + utils.UnixTimeToUTC(flow.TimestampLast) + "</p><p>Duration: " + fmt.Sprint(time.Duration(flow.Duration)) + "</p><p>TotalSize: " + humanize.Bytes(uint64(flow.TotalSize)) + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkDirection(maltego.DirectionOutputToInput)
	ent.SetLinkLabel(humanize.Bytes(uint64(flow.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(flow.TotalSize), min, max))
}
