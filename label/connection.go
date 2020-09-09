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

	"github.com/cheggaaa/pb"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// labelConnections labels type NC_Connection.
func labelConnections(wg *sync.WaitGroup, file string, alerts []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, file)
		total, errCount = netio.Count(fname)
		labelsTotal     = 0
		progress        = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName     = filepath.Join(outDir, "Connection_labeled.csv")
	)

	if errCount != nil {
		log.Fatal("failed to count audit records:", errCount)
	}

	go func() {
		r, err := netio.Open(fname, defaults.BufferSize)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header, errFileHeader := r.ReadHeader()
		if errFileHeader != nil {
			log.Fatal(errFileHeader)
		}

		if header.Type != types.Type_NC_Connection {
			die("file does not contain Connection records", header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			conn = new(types.Connection)
			co   types.AuditRecord
			pm   proto.Message
			ok   bool
		)

		pm = conn

		types.Select(conn, selection)

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
			err = r.Next(conn)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			var finalLabel string

			// check if flow has a source or destination address matching an alert
			// if not label it as normal
			for _, a := range alerts {
				var (
					alertTime = time.Unix(0, a.Timestamp)
					last      = time.Unix(0, conn.TimestampLast)
					first     = time.Unix(0, conn.TimestampFirst)
				)

				// transport protocol must match
				if a.Proto == conn.TransportProto &&

					// AND alert time must be either after or equal to first seen timestamp
					(alertTime.After(first) || alertTime.Equal(first)) &&

					// AND alert time must be either before or equal to last seen timestamp
					(alertTime.Before(last) || alertTime.Equal(last)) &&

					// AND conn source ip must either be source or destination of alert
					(conn.SrcIP == a.SrcIP || conn.SrcIP == a.DstIP) &&

					// AND conn destination ip must either be source or destination of alert
					(conn.DstIP == a.SrcIP || conn.DstIP == a.DstIP) &&

					// AND conn source port must either be source or destination of alert
					(conn.SrcPort == strconv.Itoa(a.SrcPort) || conn.SrcPort == strconv.Itoa(a.DstPort)) &&

					// AND conn destination port must either be source or destination of alert
					(conn.DstPort == strconv.Itoa(a.SrcPort) || conn.DstPort == strconv.Itoa(a.DstPort)) {
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
					_, _ = f.WriteString(strings.Join(conn.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			if len(finalLabel) != 0 {
				// add final label
				_, _ = f.WriteString(strings.Join(conn.CSVRecord(), separator) + separator + finalLabel + "\n")
				labelsTotal++

				goto read
			}

			// label as normal
			_, _ = f.WriteString(strings.Join(conn.CSVRecord(), separator) + separator + "normal\n")
		}

		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}
