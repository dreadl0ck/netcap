/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	"bufio"
	"html"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/maltego"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toConnectionsForService() {
	var (
		serviceIP   string
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

	netmaltego.ConnectionTransform(nil, func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ip string, sizes *[]int) {
		if serviceIP == "" {
			// set the serviceType we are searching for once
			parts := strings.Split(lt.Value, ":")
			if len(parts) > 1 {
				serviceIP = parts[0] // trim off port
			} else {
				serviceIP = lt.Value
			}

			log.Println("serviceType", lt.Value)
		}

		if conn.DstIP == serviceIP {
			port, err := strconv.Atoi(conn.DstPort)
			if err != nil {
				maltego.Die(err.Error(), "invalid port for connection")
			}
			service := resolvers.LookupServiceByPort(port, strings.ToLower(conn.TransportProto))
			addConn(trx, conn, path, min, max, maltego.InputToOutput, service)
		}
	})
}

func addConn(trx *maltego.Transform, conn *types.Connection, path string, min, max uint64, direction maltego.LinkDirection, service string) {
	ent := addEntityWithPath(trx, "netcap.Connection", utils.CreateFlowIdent(conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort), path)

	ent.SetLinkDirection(direction)
	ent.SetLinkLabel(strconv.FormatInt(int64(conn.NumPackets), 10) + " pkts\n" + humanize.Bytes(uint64(conn.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))
	ent.AddProperty("srcip", "SrcIP", maltego.Strict, conn.SrcIP)
	ent.AddProperty("srcport", "SrcPort", maltego.Strict, conn.SrcPort)
	ent.AddProperty("dstip", "DstIP", maltego.Strict, conn.DstIP)
	ent.AddProperty("dstport", "DstPort", maltego.Strict, conn.DstPort)
	ent.AddProperty("protocol", "Protocol", maltego.Strict, conn.TransportProto)
	ent.AddProperty("service", "Service", maltego.Strict, service)
	ent.AddProperty("totalsize", "TotalSize", maltego.Strict, strconv.Itoa(int(conn.TotalSize)))
	ent.AddProperty("apppayloadsize", "AppPayloadSize", maltego.Strict, strconv.Itoa(int(conn.AppPayloadSize)))

	ent.AddDisplayInformation(makeConversationHTML(service, conn, path), "Conversation: Client (Red), Server (Blue)")
}

func addConnection(trx *maltego.Transform, conn *types.Connection, path string, min, max uint64, direction maltego.LinkDirection) {
	i, err := strconv.Atoi(conn.DstPort)
	if err != nil {
		return
	}

	addConn(trx, conn, path, min, max, direction, resolvers.LookupServiceByPort(i, strings.ToLower(conn.TransportProto)))
}

func makeConversationHTML(service string, conn *types.Connection, path string) string {

	// TODO: tracking the correct application payload size does not always seem to work, investigate why.
	// I suspect its because the gopacket option is set to lazy and not datagrams.
	// if conn.AppPayloadSize == 0 {
	// 	return "no data transferred"
	// }

	if service == "" {
		service = "unknown"
	}

retry:
	streamFilePath := filepath.Join(
		filepath.Dir(path),
		strings.ToLower(conn.TransportProto),
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

	f, err := os.Open(streamFilePath)
	if err != nil {
		if service == "unknown" {
			service = "ascii"
			goto retry
		}
		return err.Error()
	}

	var (
		// TODO: make configurable
		size = 1024
		buf  = make([]byte, size)
	)

	n, err := bufio.NewReader(f).Read(buf)
	if err != nil && err != io.EOF {
		return err.Error()
	}

	if n < size {
		buf = buf[:n]
	} else {
		buf = append(buf, []byte("\n\n...  result truncated to "+strconv.Itoa(size)+" bytes.")...)
	}

	str := strings.ReplaceAll(html.EscapeString(strings.TrimSpace(string(buf))), "\n", "<br>")
	str = strings.ReplaceAll(str, ansi.Red, "<p style='color: red;'>")
	str = strings.ReplaceAll(str, ansi.Blue, "<p style='color: dodgerblue;'>")
	str = strings.ReplaceAll(str, ansi.Reset, "</p>")

	return maltego.EscapeText(str)
}
