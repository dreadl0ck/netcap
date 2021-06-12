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
	"errors"
	"fmt"
	"github.com/evilsocket/islazy/tui"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb"
	gzip "github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

type attacks struct {
	Attacks []*AttackInfo `yaml:"attacks"`
}

// AttackInfo models an attack and contains meta information.
// Timestamps are provided as strings to support custom time formats.
type AttackInfo struct {

	// Attack instance number
	Num int `csv:"num" yaml:"num"`

	// Attack Name
	Name string `csv:"name" yaml:"name"`

	// Attack timeframe
	Start string `csv:"start" yaml:"start"`
	End   string `csv:"end" yaml:"end"`

	// any traffic going from and towards the specified IPs in the given timeframe
	// the field value from parsed CSV is going to be split by ";"
	IPs []string `csv:"ips" yaml:"ips"`

	// Underlying Protocol(s)
	Proto string `csv:"proto" yaml:"proto"`

	// Additional notes
	Notes string `csv:"notes" yaml:"notes"`

	// Associated category
	Category string `csv:"category" yaml:"category"`

	// MITRE Tactic or Technique Name
	MITRE string `csv:"mitre" yaml:"mitre"`

	// Day of Attack
	Date string `yaml:"date" yaml:"date"`

	// Separate victims and attacks, flag any traffic BETWEEN the specified IPs.
	Victims   []string `csv:"victims" yaml:"victims"`
	Attackers []string `csv:"attackers" yaml:"attackers"`
}

// CustomLabels uses info from a csv file to label the data.
func CustomLabels(pathMappingInfo, outputPath, separator, selection string) error {
	var (
		start  = time.Now()
		labels []*attackInfo
	)
	if strings.HasSuffix(pathMappingInfo, ".csv") {
		_, labels = parseAttackInfosCSV(pathMappingInfo)
	} else {
		_, labels = parseAttackInfosYAML(pathMappingInfo)
	}
	if len(labels) == 0 {
		fmt.Println("no labels found.")
		os.Exit(0)
	}

	fmt.Println("got", len(labels), "labels")

	var rows [][]string
	for i, c := range labels {
		rows = append(rows, []string{strconv.Itoa(i + 1), c.Name})
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
		if strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) || strings.HasSuffix(f.Name(), defaults.FileExtension) {
			wg.Add(1)

			var (
				// get record name
				filename = f.Name()
				typ      = strings.TrimSuffix(strings.TrimSuffix(filename, defaults.FileExtensionCompressed), defaults.FileExtension)
			)

			// fmt.Println("type", typ)
			pbs = append(pbs, customMap(&wg, filename, typ, labels, outputPath, separator, selection))
		}
	}

	var pool *pb.Pool
	if UseProgressBars { // wait for goroutines to start and initialize
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
		if err = pool.Stop(); err != nil {
			fmt.Println("failed to stop progress bar pool:", err)
		}
	}

	fmt.Println("\ndone in", time.Since(start))
	return nil
}

// private

// internal attackInfo with parsed timestamps
type attackInfo struct {

	// Attack instance number
	Num int `csv:"num" yaml:"num"`

	// Attack Name
	Name string `csv:"name" yaml:"name"`

	// Attack timeframe
	Start time.Time `csv:"start" yaml:"start"`
	End   time.Time `csv:"end" yaml:"end"`

	// any traffic going from and towards the specified IPs in the given timeframe
	// the field value from parsed CSV is going to be split by ";"
	IPs []string `csv:"ips" yaml:"ips"`

	// Underlying Protocol(s)
	Proto string `csv:"proto" yaml:"proto"`

	// Additional notes
	Notes string `csv:"notes" yaml:"notes"`

	// Associated category
	Category string `csv:"category" yaml:"category"`

	// MITRE Tactic or Technique Name
	MITRE string `csv:"mitre" yaml:"mitre"`

	// Day of Attack
	Date time.Time `yaml:"date" yaml:"date"`

	// Separate victims and attacks, flag any traffic BETWEEN the specified IPs.
	Victims   []string `csv:"victims" yaml:"victims"`
	Attackers []string `csv:"attackers" yaml:"attackers"`
}

func parseAttackInfosYAML(path string) (labelMap map[string]*attackInfo, labels []*attackInfo) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	var atks = &attacks{}
	err = yaml.UnmarshalStrict(data, &atks)
	if err != nil {
		log.Fatal(err)
	}

	// alerts that have a duplicate timestamp
	var duplicates []*attackInfo

	// ts:alert
	labelMap = make(map[string]*attackInfo)

	for i, a := range atks.Attacks {

		start, errParseStart := time.Parse("15:04", a.Start)
		if errParseStart != nil {
			log.Fatal(errParseStart)
		}

		end, errParseEnd := time.Parse("15:04", a.End)
		if errParseEnd != nil {
			log.Fatal(errParseEnd)
		}

		// example: "2006/1/2 15:04:05"
		// from dataset: Friday-02-03-2018
		// TODO: make ts layout configurable
		date, errParseDate := time.Parse("Monday-02-01-2006", a.Date)
		if errParseDate != nil {
			log.Fatal(errParseDate)
		}

		custom := &attackInfo{
			Num:       i,     // int
			Start:     start, // time.Time
			End:       end,   // time.Time
			Victims:   a.Victims,
			Attackers: a.Attackers,
			Date:      date,
			Name:      a.Name,     // string
			Proto:     a.Proto,    // string
			Notes:     a.Notes,    // string
			Category:  a.Category, // string
		}

		// ensure no alerts with empty name are collected
		if custom.Name == "" || custom.Name == " " {
			fmt.Println("skipping entry with empty name", custom)

			continue
		}

		// count total occurrences of classification
		classificationMap[custom.Name]++

		// check if excluded
		if !excluded[custom.Name] { // append to collected alerts
			labels = append(labels, custom)

			startTSString := strconv.FormatInt(custom.Start.Unix(), 10)

			// add to label map
			if _, ok := labelMap[startTSString]; ok {
				// an alert for this timestamp already exists
				// if configured the execution will stop
				// for now the first seen alert for a timestamp will be kept
				duplicates = append(duplicates, custom)
			} else {
				labelMap[startTSString] = custom
			}
		}
	}

	return
}

func parseAttackInfosCSV(path string) (labelMap map[string]*attackInfo, labels []*attackInfo) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	r := csv.NewReader(f)

	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	// alerts that have a duplicate timestamp
	var duplicates []*attackInfo

	// ts:alert
	labelMap = make(map[string]*attackInfo)

	for _, record := range records[1:] {
		num, errConvert := strconv.Atoi(record[0])
		if errConvert != nil {
			log.Fatal(errConvert)
		}

		start, errParseStart := time.Parse("2006/1/2 15:04:05", record[2])
		if errParseStart != nil {
			log.Fatal(errParseStart)
		}

		end, errParseEnd := time.Parse("2006/1/2 15:04:05", record[3])
		if errParseEnd != nil {
			log.Fatal(errParseEnd)
		}

		// example: "2006/1/2 15:04:05"
		// from dataset: Friday-02-03-2018
		// TODO: make configurable
		date, errParseDate := time.Parse("2006/1/2", record[9])
		if errParseDate != nil {
			log.Fatal(errParseDate)
		}

		toArr := func(input string) []string {
			return strings.Split(strings.Trim(input, "\""), ";")
		}

		custom := &attackInfo{
			Num:       num,              // int
			Start:     start,            // time.Time
			End:       end,              // time.Time
			IPs:       toArr(record[4]), // []string
			Name:      record[1],        // string
			Proto:     record[5],        // string
			Notes:     record[6],        // string
			Category:  record[7],        // string
			Date:      date,
			MITRE:     record[8],
			Victims:   toArr(record[10]),
			Attackers: toArr(record[11]),
		}

		// ensure no alerts with empty name are collected
		if custom.Name == "" || custom.Name == " " {
			fmt.Println("skipping entry with empty name", custom)

			continue
		}

		// count total occurrences of classification
		classificationMap[custom.Name]++

		// check if excluded
		if !excluded[custom.Name] { // append to collected alerts
			labels = append(labels, custom)

			startTSString := strconv.FormatInt(custom.Start.Unix(), 10)

			// add to label map
			if _, ok := labelMap[startTSString]; ok {
				// an alert for this timestamp already exists
				// if configured the execution will stop
				// for now the first seen alert for a timestamp will be kept
				duplicates = append(duplicates, custom)
			} else {
				labelMap[startTSString] = custom
			}
		}
	}

	return
}

// customMap uses info from a csv file to label the data
// func customMap(wg *sync.WaitGroup, file string, typ string, labelMap map[int64]*suricataAlert, labels []*suricataAlert, outDir, separator, selection string) *pb.ProgressBar {.
func customMap(wg *sync.WaitGroup, file, typ string, labels []*attackInfo, outDir, separator, selection string) *pb.ProgressBar {
	var (
		fname           = filepath.Join(outDir, file)
		total, errCount = netio.Count(fname)
		labelsTotal     = 0
		outFileName     = filepath.Join(outDir, typ+"_labeled.csv.gz")
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

		gzipWriter := gzip.NewWriter(f)

		// To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
		// You should at least have a block size of 100k and at least a number of blocks that match the number of cores
		// you would like to utilize, but about twice the number of blocks would be the best.
		if err = gzipWriter.SetConcurrency(defaults.CompressionBlockSize, runtime.GOMAXPROCS(0)*2); err != nil {
			log.Fatal("failed to configure compression package: ", err)
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
		_, err = gzipWriter.Write([]byte(strings.Join(p.CSVHeader(), separator) + separator + "result" + "\n"))
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

			var label string

			// check if flow has a source or destination address matching an alert
			// if not label it as normal
			for _, l := range labels {
				var numMatches int

				// check if any of the addresses from the labeling info
				// is either source or destination of the current audit record
				if len(l.IPs) > 0 {
					for _, addr := range l.IPs {
						if p.Src() == addr || p.Dst() == addr {
							numMatches++
						}
					}
				} else {
					// for each attacker IP
					for _, addr := range l.Attackers {

						// check if src or dst of packet is from an attacker
						if p.Src() == addr || p.Dst() == addr {

							numMatches++

							// for each victim
							for _, victimAddr := range l.Victims {

								// if either the src or dst addr of the packet is a victim
								if p.Src() == victimAddr || p.Dst() == victimAddr {
									numMatches++

									// TODO: break from outer loop as well
									break
								}
							}
						}
					}
				}

				if numMatches != 2 {
					// label as normal
					_, _ = gzipWriter.Write([]byte(strings.Join(p.CSVRecord(), separator) + separator + "normal\n"))

					continue
				}

				// verify time interval of audit record is within the attack period
				auditRecordTime := time.Unix(0, p.Time()).UTC().Add(8 * time.Hour)

				// TODO: move this check up? likely the fastest check
				// if the audit record has a timestamp in the attack period
				if (l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime)) ||

					// or matches exactly the one on the audit record
					l.Start.Equal(auditRecordTime) || l.End.Equal(auditRecordTime) {
					if Debug {
						fmt.Println("-----------------------", typ, l.Name, l.Category)
						fmt.Println("flow:", p.Src(), "->", p.Dst(), "addr:", "attack ips:", l.IPs)
						fmt.Println("start", l.Start)
						fmt.Println("end", l.End)
						fmt.Println("auditRecordTime", auditRecordTime)
						fmt.Println("(l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime))", l.Start.Before(auditRecordTime) && l.End.After(auditRecordTime))
						fmt.Println("l.Start.Equal(auditRecordTime)", l.Start.Equal(auditRecordTime))
						fmt.Println("l.End.Equal(auditRecordTime))", l.End.Equal(auditRecordTime))
					}

					// only if it is not already part of the label
					if !strings.Contains(label, l.Category) {
						if label == "" {
							label = l.Category
						} else {
							label += " | " + l.Category
						}
					}
				}
			}

			if len(label) != 0 {
				if strings.HasPrefix(label, " |") {
					log.Fatal("invalid label: ", label)
				}

				// add label
				_, _ = gzipWriter.Write([]byte(strings.Join(p.CSVRecord(), separator) + separator + label + "\n"))
				labelsTotal++
			} else {
				// label as normal
				_, _ = gzipWriter.Write([]byte(strings.Join(p.CSVRecord(), separator) + separator + "normal\n"))
			}
		}

		err = gzipWriter.Flush()
		if err != nil {
			log.Fatal(err)
		}

		err = gzipWriter.Close()
		if err != nil {
			log.Fatal(err)
		}

		finish(wg, r, f, labelsTotal, outFileName, progress)
	}()

	return progress
}
