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
	"strings"
	"sync"

	"github.com/cheggaaa/pb"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// labelTLS labels type NC_TLSClientHello.
func labelTLS(wg *sync.WaitGroup, file string, alerts []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, file)
		total, errCount = netio.Count(fname)
		labelsTotal     = 0
		progress        = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName     = filepath.Join(outDir, "TLS_labeled.csv")
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
		if header.Type != types.Type_NC_TLSClientHello {
			die("file does not contain HTTP records", header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			tls = new(types.TLSClientHello)
			co  types.AuditRecord
			pm  proto.Message
			ok  bool
		)
		pm = tls

		types.Select(tls, selection)

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
			err = r.Next(tls)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			var finalLabel string

			// this labels the TLS audit record as malicious
			// if ANY packet of the birectional connection initiated by the TLS handshake was classified as malicious
			for _, a := range alerts {
				// transport proto must be TCP
				if a.Proto == "TCP" &&

					// AND timestamp of alert must be equal to handshake packet or after it
					(a.Timestamp == tls.Timestamp || a.Timestamp > tls.Timestamp) &&

					// AND source ip must either be source or destination of alert
					(tls.SrcIP == a.SrcIP || tls.SrcIP == a.DstIP) &&

					// AND destination ip must either be source or destination of alert
					(tls.DstIP == a.SrcIP || tls.DstIP == a.DstIP) &&

					// AND source port must either be source or destination of alert
					(int32(a.SrcPort) == tls.SrcPort || int32(a.SrcPort) == tls.DstPort) &&

					// AND destination port must either be source or destination of alert
					(int32(a.DstPort) == tls.SrcPort || int32(a.DstPort) == tls.DstPort) {
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
					_, _ = f.WriteString(strings.Join(tls.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			if len(finalLabel) != 0 {
				// add final label
				_, _ = f.WriteString(strings.Join(tls.CSVRecord(), separator) + separator + finalLabel + "\n")
				labelsTotal++

				goto read
			}

			// label as normal
			_, _ = f.WriteString(strings.Join(tls.CSVRecord(), separator) + separator + "normal\n")
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}
