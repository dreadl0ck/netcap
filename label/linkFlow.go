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

package label

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
	pb "gopkg.in/cheggaaa/pb.v1"
)

// LinkFlow labels LinkFlows.
func LinkFlow(wg *sync.WaitGroup, file string, alerts []*SuricataAlert, outDir, separator, selection string) *pb.ProgressBar {

	// @TODO:
	// LinkFlows currently cannot be labeled
	// since suricata currently does not provide the MAC address of an alert...
	// as discussed here: https://redmine.openinfosecfoundation.org/issues/962
	// there might an option to enable it for the eve log in the future
	return nil

	var (
		fname       = filepath.Join(outDir, file)
		total       = netcap.Count(fname)
		labelsTotal = 0
		progress    = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName = filepath.Join(outDir, "LinkFlow_labeled.csv")
	)

	go func() {
		r, err := netcap.Open(fname, netcap.DefaultBufferSize)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header := r.ReadHeader()
		if header.Type != types.Type_NC_LinkFlow {
			panic("file does not contain LinkFlow records: " + header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			flow = new(types.LinkFlow)
			co   types.AuditRecord
			pm   proto.Message
			ok   bool
		)
		pm = flow

		types.Select(flow, selection)

		if co, ok = pm.(types.AuditRecord); !ok {
			panic("type does not implement types.AuditRecord interface")
		}

		// write header
		_, err = f.WriteString(strings.Join(co.CSVHeader(), separator) + separator + "result" + "\n")
		if err != nil {
			panic(err)
		}

	read:
		for {
			err := r.Next(flow)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			// check if flow has a source or destination adress matching an alert
			// if not label it as normal
			for _, a := range alerts {
				// transport protocol must match
				if a.Proto == flow.Proto { // &&
					// // AND conn source ip must either be source or destination of alert
					// (flow.SrcIP == a.SrcIP || flow.SrcIP == a.DstIP) &&
					// // AND conn destination ip must either be source or destination of alert
					// (flow.DstIP == a.SrcIP || flow.DstIP == a.DstIP) &&
					// // AND conn source port must either be source or destination of alert
					// (flow.SrcPort == strconv.Itoa(a.SrcPort) || flow.SrcPort == strconv.Itoa(a.DstPort)) &&
					// // AND conn destination port must either be source or destination of alert
					// (flow.DstPort == strconv.Itoa(a.SrcPort) || flow.DstPort == strconv.Itoa(a.DstPort)) {

					// ((a.DstIP == conn.DstIP && a.SrcIP == conn.SrcIP) ||
					// (a.DstIP == conn.SrcIP && a.SrcIP == conn.DstIP)) &&

					// add label
					f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			// label as normal
			f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + "normal\n")
		}

		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()
	return nil
}
