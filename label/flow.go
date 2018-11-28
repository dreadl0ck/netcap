/*
 * NETCAP - Network Capture Toolkit
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
	pb "gopkg.in/cheggaaa/pb.v1"
)

// Flows labels type NC_Flow
func Flows(wg *sync.WaitGroup, file string, alerts []*SuricataAlert, outDir, separator, selection string) *pb.ProgressBar {

	var (
		fname       = filepath.Join(outDir, "Flow.ncap.gz")
		total       = netcap.Count(fname)
		labelsTotal = 0
		progress    = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName = filepath.Join(outDir, "Flow_labeled.csv")
	)

	go func() {
		r, err := netcap.Open(fname)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header := r.ReadHeader()
		if header.Type != types.Type_NC_Flow {
			panic("file does not contain Flow records: " + header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			flow = new(types.Flow)
			fl   types.CSV
			pm   proto.Message
			ok   bool
		)
		pm = flow

		types.Select(flow, selection)

		if fl, ok = pm.(types.CSV); !ok {
			panic("type does not implement CSV interface")
		}

		// write header
		_, err = f.WriteString(strings.Join(fl.CSVHeader(), separator) + separator + "result" + "\n")
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

			// Unidirectional Flows
			// check if flow has a source or destination adress matching an alert
			// also checks ports and transport proto
			// if not label it as normal
			for _, a := range alerts {

				var (
					alertTime = utils.StringToTime(a.Timestamp)
					last      = utils.StringToTime(flow.TimestampLast)
					first     = utils.StringToTime(flow.TimestampFirst)
				)

				// alert time must be either after or equal to first seen timestamp
				if (alertTime.After(first) || alertTime.Equal(first)) &&

					// AND alert time must be either before or equal to last seen timestamp
					(alertTime.Before(last) || alertTime.Equal(last)) &&

					// AND destination ip must match
					a.DstIP == flow.DstIP &&

					// AND source ip must match
					a.SrcIP == flow.SrcIP &&

					// AND destination port must match
					strconv.Itoa(a.DstPort) == flow.DstPort &&

					// AND source port must match
					strconv.Itoa(a.SrcPort) == flow.SrcPort &&

					// AND transport protocol must match
					a.Proto == flow.TransportProto {

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
	return progress
}
