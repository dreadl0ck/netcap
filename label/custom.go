/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2019 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"
	pb "gopkg.in/cheggaaa/pb.v1"
)

type Custom struct {
	AttackNumber   int
	StartTime      int64
	EndTime        int64
	AttackDuration time.Duration
	AttackPoints   []string
	Adresses       []string
	AttackName     string
	AttackType     string
	Intent         string
	ActualChange   string
	Notes          string
}

func ParseCustomConfig(path string) (labelMap map[string]*Custom, labels []*Custom) {

	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	// alerts that have a duplicate timestamp
	var duplicates = []*Custom{}

	// ts:alert
	labelMap = make(map[string]*Custom)

	for _, record := range records[1:] {

		num, err := strconv.Atoi(record[0])
		if err != nil {
			log.Fatal(err)
		}

		start, err := strconv.ParseInt(record[2], 10, 64)
		if err != nil {
			log.Fatal(err)
		}

		end, err := strconv.ParseInt(record[3], 10, 64)
		if err != nil {
			log.Fatal(err)
		}

		duration, err := time.ParseDuration(record[4])
		if err != nil {
			log.Fatal(err)
		}

		toArr := func(input string) []string {
			return strings.Split(strings.Trim(input, "\""), ",")
		}

		custom := &Custom{
			AttackNumber:   num,                        // int
			StartTime:      time.Unix(start, 0).Unix(), // int64
			EndTime:        time.Unix(end, 0).Unix(),   // int64
			AttackDuration: duration,                   // time.Duration
			AttackPoints:   toArr(record[5]),           // []string
			Adresses:       toArr(record[6]),           // []string
			AttackName:     record[7],                  // string
			AttackType:     record[8],                  // string
			Intent:         record[9],                  // string
			ActualChange:   record[10],                 // string
			Notes:          record[11],                 // string
		}

		// ensure no alerts with empty name are collected
		if custom.AttackName == "" || custom.AttackName == " " {
			fmt.Println("skipping entry with empty name", custom)
			continue
		}

		// count total occurrences of classification
		ClassificationMap[custom.AttackName]++

		// check if excluded
		if !excluded[custom.AttackName] {

			// append to collected alerts
			labels = append(labels, custom)

			startTsString := strconv.FormatInt(custom.StartTime, 10)

			// add to label map
			if _, ok := labelMap[startTsString]; ok {
				// an alert for this timestamp already exists
				// if configured the execution will stop
				// for now the first seen alert for a timestamp will be kept
				duplicates = append(duplicates, custom)
			} else {
				labelMap[startTsString] = custom
			}
		}
	}

	return
}

// CustomLabels uses info from a csv file to label the data
func CustomLabels(pathMappingInfo, outputPath string, useDescription bool, separator, selection string) error {

	fmt.Println("CustomLabels")

	var (
		start            = time.Now()
		labelMap, labels = ParseCustomConfig(pathMappingInfo)
	)
	if len(labels) == 0 {
		fmt.Println("no labels found.")
		os.Exit(0)
	}

	fmt.Println("got", len(labels), "labels")

	rows := [][]string{}
	for i, c := range labels {
		rows = append(rows, []string{strconv.Itoa(i + 1), c.AttackName})
	}

	// print alert summary
	tui.Table(os.Stdout, []string{"Num", "AttackName"}, rows)
	fmt.Println()

	// apply labels to data
	// set outDir to current dir or flagOut
	var outDir string
	if outputPath != "" {
		outDir = outputPath
	} else {
		outDir = "."
	}

	// label all layer data in outDir
	// first read directory
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		return err
	}

	var (
		wg  sync.WaitGroup
		pbs []*pb.ProgressBar
	)

	// iterate over all files in dir
	for _, f := range files {

		// check if its an audit record file
		if strings.HasSuffix(f.Name(), ".ncap.gz") || strings.HasSuffix(f.Name(), ".ncap") {
			wg.Add(1)

			var (
				// get record name
				filename = f.Name()
				typ      = strings.TrimSuffix(strings.TrimSuffix(filename, ".ncap.gz"), ".ncap")
			)

			fmt.Println("type", typ)
			pbs = append(pbs, CustomMap(&wg, filename, typ, labelMap, labels, outputPath, separator, selection))
		}
	}

	var pool *pb.Pool
	if UseProgressBars {

		// wait for goroutines to start and initialize
		// otherwise progress bars will bug
		time.Sleep(3 * time.Second)

		// start pool
		pool, err = pb.StartPool(pbs...)
		if err != nil {
			return err
		}
		utils.ClearScreen()
	}

	wg.Wait()

	if UseProgressBars {
		// close pool
		if err := pool.Stop(); err != nil {
			fmt.Println("failed to stop progress bar pool:", err)
		}
	}

	fmt.Println("\ndone in", time.Since(start))
	return nil
}

// CustomMap uses info from a csv file to label the data
//func CustomMap(wg *sync.WaitGroup, file string, typ string, labelMap map[string]*SuricataAlert, labels []*SuricataAlert, outDir, separator, selection string) *pb.ProgressBar {
func CustomMap(wg *sync.WaitGroup, file string, typ string, labelMap map[string]*Custom, labels []*Custom, outDir, separator, selection string) *pb.ProgressBar {

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
		nextRecord:
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
				for _, l := range labels {

					var match bool

					//fmt.Println(p.Src(), p.Dst())

					// check if any of the addresses from the labeling info
					// is either source or destination of the current audit record
					for _, addr := range l.Adresses {
						if p.Src() == addr || p.Dst() == addr {
							match = true
						}
					}
					if !match {
						// label as normal
						f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + "normal\n")
						goto nextRecord
					}

					// verify time interval of audit record is within the attack period
					start := time.Unix(l.StartTime, 0)
					end := time.Unix(l.EndTime, 0)
					auditRecordTime := utils.StringToTime(p.Time())

					// fmt.Println("start", start)
					// fmt.Println("end", end)
					// fmt.Println("auditRecordTime", auditRecordTime)

					// if the audit record has a timestamp in the attack period
					if start.Before(auditRecordTime) && end.After(auditRecordTime) {

						// only if it is not already part of the label
						if !strings.Contains(label, l.AttackName) {
							if label == "" {
								label = l.AttackName
							} else {
								label += " | " + l.AttackName
							}
						}
					}
				}

				if len(label) != 0 {
					if strings.HasPrefix(label, " |") {
						log.Fatal("invalid label: ", label)
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
				if a, ok := labelMap[p.Time()]; ok {
					// add label
					f.WriteString(strings.Join(p.CSVRecord(), separator) + separator + a.AttackName + "\n")
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
