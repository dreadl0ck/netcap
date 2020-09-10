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
			serviceType = lt.Values["service"]
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
	ent := trx.AddEntityWithPath("netcap.Connection", conn.UID, path)

	ent.SetLinkLabel(strconv.FormatInt(int64(conn.NumPackets), 10) + " pkts\n" + humanize.Bytes(uint64(conn.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))
	ent.AddProperty("srcip", "SrcIP", "strict", conn.SrcIP)
	ent.AddProperty("srcport", "SrcPort", "strict", conn.SrcPort)
	ent.AddProperty("dstip", "DstIP", "strict", conn.DstIP)
	ent.AddProperty("dstport", "DstPort", "strict", conn.DstPort)
}