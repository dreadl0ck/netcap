package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"strconv"
	"strings"
)

func toConnectionsForService() {

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

	maltego.ConnectionTransform(nil, func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ip string, sizes *[]int) {
		if serviceType == "" {
			// set the serviceType we are searching for once
			serviceType = lt.Value
		}

		i, err := strconv.Atoi(conn.DstPort)
		if err != nil {
			return
		}

		service := resolvers.LookupServiceByPort(i, strings.ToLower(conn.TransportProto))
		if service == serviceType {
			addConn(trx, conn, path, min, max)
		}
	})
}

func addConn(trx *maltego.Transform, conn *types.Connection, path string, min, max uint64) {
	ent := trx.AddEntityWithPath("netcap.Connection", utils.CreateFlowIdent(conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort), path)

	ent.SetLinkLabel(strconv.FormatInt(int64(conn.NumPackets), 10) + " pkts\n" + humanize.Bytes(uint64(conn.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))
	ent.AddProperty("srcip", "SrcIP", maltego.Strict, conn.SrcIP)
	ent.AddProperty("srcport", "SrcPort", maltego.Strict, conn.SrcPort)
	ent.AddProperty("dstip", "DstIP", maltego.Strict, conn.DstIP)
	ent.AddProperty("dstport", "DstPort", maltego.Strict, conn.DstPort)
}
