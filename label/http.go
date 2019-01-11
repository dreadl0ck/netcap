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

// HTTP labels http.
func HTTP(wg *sync.WaitGroup, file string, alerts []*SuricataAlert, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname       = filepath.Join(outDir, file)
		total       = netcap.Count(fname)
		labelsTotal = 0
		progress    = pb.New(int(total)).Prefix(utils.Pad(utils.TrimFileExtension(file), 25))
		outFileName = filepath.Join(outDir, "HTTP_labeled.csv")
	)

	go func() {
		r, err := netcap.Open(fname)
		if err != nil {
			panic(err)
		}

		// read netcap header
		header := r.ReadHeader()
		if header.Type != types.Type_NC_HTTP {
			panic("file does not contain HTTP records: " + header.Type.String())
		}

		// outfile handle
		f, err := os.Create(outFileName)
		if err != nil {
			panic(err)
		}

		var (
			http = new(types.HTTP)
			co   types.CSV
			pm   proto.Message
			ok   bool
		)
		pm = http

		types.Select(http, selection)

		if co, ok = pm.(types.CSV); !ok {
			panic("type does not implement CSV interface")
		}

		// write header
		_, err = f.WriteString(strings.Join(co.CSVHeader(), separator) + separator + "result" + "\n")
		if err != nil {
			panic(err)
		}

	read:
		for {
			err := r.Next(http)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			if UseProgressBars {
				progress.Increment()
			}

			var finalLabel string

			// The HTTP summary structure is treated like a bidirectional flow
			// since an alert can either refer to the HTTP request or the response
			// additionally one of the involved ports must be 80
			for _, a := range alerts {

				// if http request timestamp matches an alert -> label instantly
				if a.Timestamp == http.Timestamp ||

					// OR transport proto must be TCP
					(a.Proto == "TCP" &&

						// AND http srcIP must either be source or destination of alert
						(http.SrcIP == a.SrcIP || http.SrcIP == a.DstIP) &&

						// AND http dstIP must either be source or destination of alert
						(http.DstIP == a.SrcIP || http.DstIP == a.DstIP)) &&

						// AND either source or dest port of alert must be port 80
						(a.SrcPort == 80 || a.DstPort == 80) {

					// fmt.Println("DEBUG: http label match, http TS", http.Timestamp, "alert TS", a.Timestamp)

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
					f.WriteString(strings.Join(http.CSVRecord(), separator) + separator + a.Classification + "\n")
					labelsTotal++

					goto read
				}
			}

			if len(finalLabel) != 0 {
				// add final label
				f.WriteString(strings.Join(http.CSVRecord(), separator) + separator + finalLabel + "\n")
				labelsTotal++
				goto read
			}

			// label as normal
			f.WriteString(strings.Join(http.CSVRecord(), separator) + separator + "normal\n")
		}
		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()
	return progress
}
