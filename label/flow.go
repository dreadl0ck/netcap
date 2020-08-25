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
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"gopkg.in/cheggaaa/pb.v1"

	"github.com/dreadl0ck/netcap/defaults"
	io2 "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// labelFlows labels type NC_Flow.
func labelFlows(wg *sync.WaitGroup, file string, alerts []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, "Flow.ncap.gz")
		total, errCount = io2.Count(fname)
		labelsTotal     = 0
		progress        = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName     = filepath.Join(outDir, "Flow_labeled.csv")
	)
	if errCount != nil {
		log.Fatal("failed to count audit records:", errCount)
	}

	go func() {
		r, err := io2.Open(fname, defaults.BufferSize)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header, errFileHeader := r.ReadHeader()
		if errFileHeader != nil {
			log.Fatal(errFileHeader)
		}
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
			fl   types.AuditRecord
			pm   proto.Message
			ok   bool
		)
		pm = flow

		types.Select(flow, selection)

		if fl, ok = pm.(types.AuditRecord); !ok {
			panic("type does not implement types.AuditRecord interface")
		}

		// write header
		_, err = f.WriteString(strings.Join(fl.CSVHeader(), separator) + separator + "result" + "\n")
		if err != nil {
			panic(err)
		}

	read:
		for {
			err = r.Next(flow)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			var finalLabel string

			// Unidirectional Flows
			// check if flow has a source or destination address matching an alert
			// also checks ports and transport proto
			// if not label it as normal
			for _, a := range alerts {
				var (
					alertTime = time.Unix(0, a.Timestamp)
					last      = time.Unix(0, flow.TimestampLast)
					first     = time.Unix(0, flow.TimestampFirst)
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
					_, _ = f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			if len(finalLabel) != 0 {
				// add final label
				_, _ = f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + finalLabel + "\n")
				labelsTotal++

				goto read
			}

			// label as normal
			_, _ = f.WriteString(strings.Join(flow.CSVRecord(), separator) + separator + "normal\n")
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}
