package transform

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

func toIANAServicesForConnections() {
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
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.ConnectionTransform(
		maltego.CountOutgoingConnBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ipaddr string, top12 *[]int) {
			i, err := strconv.Atoi(conn.DstPort)
			if err != nil {
				return
			}

			service := resolvers.LookupServiceByPort(i, strings.ToLower(conn.TransportProto))
			if service != "" {
				ent := trx.AddEntityWithPath("netcap.Service", service, path)
				ent.SetLinkLabel(humanize.Bytes(uint64(conn.TotalSize)))
				ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))
				ent.AddProperty("ip", "IP", maltego.Strict, conn.DstIP)
				ent.AddProperty("port", "Port", maltego.Strict, conn.DstPort)
			}
		},
	)
}
