package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"os"
	"strconv"
	"strings"
)

func ToIANAServices() {

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.FlowTransform(
		maltego.CountOutgoingFlowBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, flow *types.Flow, min, max uint64, profilesFile string, mac string, ipaddr string, top12 *[]int) {

			i, err := strconv.Atoi(flow.DstPort)
			if err != nil {
				return
			}

			service := resolvers.LookupServiceByPort(i, strings.ToLower(flow.TransportProto))
			if service != "" {
				ent := trx.AddEntity("netcap.Service", service)
				ent.SetType("netcap.Service")
				ent.SetValue(service)

				ent.SetLinkLabel(humanize.Bytes(uint64(flow.TotalSize)))
				ent.SetLinkColor("#000000")
				ent.SetLinkThickness(maltego.GetThickness(uint64(flow.TotalSize), min, max))
			}
		},
	)
}
