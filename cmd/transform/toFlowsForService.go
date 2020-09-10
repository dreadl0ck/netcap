package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"strconv"
	"strings"
)

func toFlowsForService() {

	var (
		serviceType string
		resolverLog = zap.New(zapcore.NewNopCore())
	)

	defer func() {
		err := resolverLog.Sync()
		if err != nil {
			log.Println(err)
		}
	}()

	resolvers.SetLogger(resolverLog)

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.FlowTransform(nil, func(lt maltego.LocalTransform, trx *maltego.Transform, flow *types.Flow, min, max uint64, path string, mac string, ip string, sizes *[]int) {
		if serviceType == "" {
			// set the serviceType we are searching for once
			serviceType = lt.Values["service"]
		}

		i, err := strconv.Atoi(flow.DstPort)
		if err != nil {
			return
		}

		service := resolvers.LookupServiceByPort(i, strings.ToLower(flow.TransportProto))
		if service == serviceType {
			addFlow(trx, flow, path, min, max)
			return
		}

		// for flows, we have to check the other direction as well
		i, err = strconv.Atoi(flow.SrcPort)
		if err != nil {
			return
		}

		service = resolvers.LookupServiceByPort(i, strings.ToLower(flow.TransportProto))
		if service == serviceType {
			addFlow(trx, flow, path, min, max)
		}
	})
}

func addFlow(trx *maltego.Transform, flow *types.Flow, path string, min, max uint64) {
	ent := trx.AddEntityWithPath("netcap.Flow", flow.UID, path)
	ent.SetLinkLabel(strconv.FormatInt(int64(flow.NumPackets), 10) + " pkts\n" + humanize.Bytes(uint64(flow.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(flow.TotalSize), min, max))
	ent.AddProperty("srcip", "SrcIP", "strict", flow.SrcIP)
	ent.AddProperty("srcport", "SrcPort", "strict", flow.SrcPort)
	ent.AddProperty("dstip", "DstIP", "strict", flow.DstIP)
	ent.AddProperty("dstport", "DstPort", "strict", flow.DstPort)
}