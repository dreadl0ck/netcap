package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"html"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
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
			addConn(trx, conn, path, min, max, service)
		}
	})
}

func addConn(trx *maltego.Transform, conn *types.Connection, path string, min, max uint64, service string) {
	ent := trx.AddEntityWithPath("netcap.Connection", utils.CreateFlowIdent(conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort), path)

	ent.SetLinkLabel(strconv.FormatInt(int64(conn.NumPackets), 10) + " pkts\n" + humanize.Bytes(uint64(conn.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))
	ent.AddProperty("srcip", "SrcIP", maltego.Strict, conn.SrcIP)
	ent.AddProperty("srcport", "SrcPort", maltego.Strict, conn.SrcPort)
	ent.AddProperty("dstip", "DstIP", maltego.Strict, conn.DstIP)
	ent.AddProperty("dstport", "DstPort", maltego.Strict, conn.DstPort)
	ent.AddProperty("protocol", "Protocol", maltego.Strict, conn.TransportProto)
	ent.AddProperty("service", "Service", maltego.Strict, service)

	ent.AddDisplayInformation(makeConversationHTML(service, conn, path), "Conversation: Client (Red), Server (Blue)")
}

func makeConversationHTML(service string, conn *types.Connection, path string) string {
	streamFilePath := filepath.Join(
		filepath.Dir(path),
		strings.ToLower(conn.TransportProto)+"Connections",
		service,
		utils.CleanIdent(
			utils.CreateFlowIdent(
				conn.SrcIP,
				conn.SrcPort,
				conn.DstIP,
				conn.DstPort,
			),
		)+".bin",
	)

	log.Println("path", streamFilePath)

	data, err := ioutil.ReadFile(streamFilePath)
	if err != nil {
		return err.Error()
	}
	str := strings.ReplaceAll(html.EscapeString(string(data)), "\n", "<br>")
	str = strings.ReplaceAll(str, ansi.Red, "<p style='color: red;'>")
	str = strings.ReplaceAll(str, ansi.Blue, "<p style='color: dodgerblue;'>")
	str = strings.ReplaceAll(str, ansi.Reset, "</p>")

	return maltego.EscapeText(str)
}
