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

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// CollectLabels indicates whether labels should be collected.
var CollectLabels bool

// labelLayer labels packets of a given gopacket.LayerType string.
func labelLayer(wg *sync.WaitGroup, file string, typ string, labelMap map[int64]*suricataAlert, labels []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, file)
		total, errCount = netio.Count(fname)
		labelsTotal     = 0
		outFileName     = filepath.Join(outDir, typ+"_labeled.csv")
		progress        = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
	)

	if errCount != nil {
		log.Fatal("failed to count audit records:", errCount)
	}

	go func() {
		// open layer data file
		r, err := netio.Open(fname, defaults.BufferSize)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header, errFileHeader := r.ReadHeader()
		if errFileHeader != nil {
			log.Fatal(errFileHeader)
		}

		// create outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			record = netio.InitRecord(header.Type)
			ok     bool
			p      types.AuditRecord
		)

		// check if we can decode it as CSV
		if p, ok = record.(types.AuditRecord); !ok {
			panic("type does not implement types.AuditRecord interface:" + typ)
		}

		// run selection
		types.Select(record, selection)

		// write header
		_, err = f.WriteString(strings.Join(p.CSVHeader(), separator) + separator + "result" + "\n")
		if err != nil {
			panic(err)
		}

		for {
			err = r.Next(record)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			// collect labels for layer
			// e.g: there are two alerts for the same timestamp with different classifications
			// they label will then contain both separated by a pipe symbol
			if CollectLabels {

				var label string

				// check if flow has a source or destination address matching an alert
				// if not label it as normal
				for _, a := range labels {
					// if the layer audit record has a timestamp of an alert
					if a.Timestamp == p.Time() {
						// only if it is not already part of the label
						if !strings.Contains(label, a.Classification) {
							if label == "" {
								label = a.Classification
							} else {
								label += " | " + a.Classification
							}
						}
					}
				}

				if len(label) != 0 {
					if strings.HasPrefix(label, " |") {
						log.Fatal("invalid label: ", label)
					}

					// add label
					_, _ = f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + label + "\n")
					labelsTotal++
				} else {
					// label as normal
					_, _ = f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + "normal\n")
				}
			} else {
				// layers are mapped by timestamp
				// this preserves only the first label seen for each timestamp
				if a, exists := labelMap[p.Time()]; exists {
					// add label
					_, _ = f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++
				} else {
					// label as normal
					_, _ = f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + "normal\n")
				}
			}
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}
