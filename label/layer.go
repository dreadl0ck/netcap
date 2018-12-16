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
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	pb "gopkg.in/cheggaaa/pb.v1"
)

var CollectLabels bool

// Layer labels packets of a given gopacket.LayerType string
func Layer(wg *sync.WaitGroup, file string, typ string, labelMap map[string]*SuricataAlert, labels []*SuricataAlert, outDir, separator, selection string) *pb.ProgressBar {

	var (
		fname       = filepath.Join(outDir, file)
		total       = netcap.Count(fname)
		labelsTotal = 0
		outFileName = filepath.Join(outDir, typ+"_labeled.csv")
		progress    = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
	)

	go func() {

		// open layer data file
		r, err := netcap.Open(fname)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header := r.ReadHeader()

		// create outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			record = netcap.InitRecord(header.Type)
			ok     bool
			p      types.CSV
		)

		// check if we can decode it as CSV
		if p, ok = record.(types.CSV); !ok {
			panic("type does not implement types.CSV interface:" + typ)
		}

		// run selection
		types.Select(record, selection)

		// write header
		_, err = f.WriteString(strings.Join(p.CSVHeader(), separator) + separator + "result" + "\n")
		if err != nil {
			panic(err)
		}

		for {
			err := r.Next(record)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
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

				// check if flow has a source or destination adress matching an alert
				// if not label it as normal
				for _, a := range labels {

					// if the layer audit record has a timestamp of an alert
					if a.Timestamp == p.NetcapTimestamp() {

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
						log.Fatal("BULLSHIT:", label)
					}

					// add label
					f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + label + "\n")
					labelsTotal++
				} else {
					// label as normal
					f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + "normal\n")
				}
			} else {
				// layers are mapped by timestamp
				// this preserves only the first label seen for each timestamp
				if a, ok := labelMap[p.NetcapTimestamp()]; ok {
					// add label
					f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++
				} else {
					// label as normal
					f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + "normal\n")
				}
			}
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}
