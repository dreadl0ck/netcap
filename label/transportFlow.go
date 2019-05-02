/*
 * NETCAP - Traffic Analysis Framework
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
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
	pb "gopkg.in/cheggaaa/pb.v1"
)

// TransportFlow labels TransportFlow
func TransportFlow(wg *sync.WaitGroup, file string, alerts []*SuricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname       = filepath.Join(outDir, file)
		total       = netcap.Count(fname)
		labelsTotal = 0
		progress    = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName = filepath.Join(outDir, "TransportFlow_labeled.csv")
	)

	go func() {
		r, err := netcap.Open(fname)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header := r.ReadHeader()
		if header.Type != types.Type_NC_TransportFlow {
			panic("file does not contain Connection records: " + header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			flow = new(types.TransportFlow)
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

			var finalLabel string

			// check if flow has a source or destination adress matching an alert
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

					// AND transport protocol must match
					a.Proto == flow.Proto &&

					// AND flow source port must either be source or destination of alert
					(flow.SrcPort == int32(a.SrcPort) || flow.SrcPort == int32(a.DstPort)) &&

					// AND flow destination port must either be source or destination of alert
					(flow.DstPort == int32(a.SrcPort) || flow.DstPort == int32(a.DstPort)) {

					if CollectLabels {
						// only if it is not already part of the label
						if !strings.Contains(finalLabel, a.Classification) {
							if finalLabel == "" {
								finalLabel = a.Classification
							} else {
								finalLabel += " | " + a.Classification
							}
						}
						continue
					}

					// add label
					f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			if len(finalLabel) != 0 {
				// add final label
				f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + finalLabel + "\n")
				labelsTotal++
				goto read
			}

			// label as normal
			f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + "normal\n")
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()
	return progress
}
