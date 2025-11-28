/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

// labelIPv6 labels type NC_IPv6.
func labelIPv6(wg *sync.WaitGroup, file string, alerts []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, "IPv6.ncap.gz")
		total, errCount = netio.Count(fname)
		labelsTotal     = 0
		progress        = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName     = filepath.Join(outDir, "IPv6_labeled.csv")
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
		if header.Type != types.Type_NC_IPv6 {
			die("file does not contain IPv6 records", header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			ip6 = new(types.IPv6)
			fl  types.AuditRecord
			pm  proto.Message
			ok  bool
		)
		pm = ip6

		types.Select(ip6, selection)

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
			err = r.Next(ip6)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			var finalLabel string

			// Unidirectional IPv6 packets
			// checks if packet has a source or destination ip matching an alert
			for _, a := range alerts {
				// must be a IPv6 packet
				if a.Proto == "IPv6" &&

					// AND timestamp must match
					a.Timestamp == ip6.Timestamp &&

					// AND destination ip must match
					a.DstIP == ip6.DstIP &&

					// AND source ip must match
					a.SrcIP == ip6.SrcIP {
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
					_, _ = f.WriteString(strings.Join(ip6.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			if len(finalLabel) != 0 {
				// add final label
				_, _ = f.WriteString(strings.Join(ip6.CSVRecord(), separator) + separator + finalLabel + "\n")
				labelsTotal++

				goto read
			}

			// label as normal
			_, _ = f.WriteString(strings.Join(ip6.CSVRecord(), separator) + separator + "normal\n")
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()
	return progress
}
