package transform

import (
	"os"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

func ToIANAServices() {

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.FlowTransform(
		maltego.CountOutgoingFlowBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, flow *types.Flow, min, max uint64, profilesFile string, mac string, ipaddr string, top12 *[]int) {

			i, err := strconv.Atoi(flow.DstPort)
			if err != nil {
				return
			}

			service := resolvers.LookupServiceByPort(i, strings.ToLower(flow.TransportProto))
			if service != "" {
				ent := trx.AddEntity("netcap.Service", service)
				ent.SetLinkLabel(humanize.Bytes(uint64(flow.TotalSize)))
				ent.SetLinkThickness(maltego.GetThickness(uint64(flow.TotalSize), min, max))
			}
		},
	)
}
