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

package main

import (
	"encoding/json"
	"github.com/dreadl0ck/netcap/encoder"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TODO: integrate core functionality into NETCAP and add this tool as cmd/analyze
// we need the following:
// - a model for encoded values and the option to store and load it between multiple executions.
// - encoding strategies to map categorical values into numerical ones
// - normalization strategies

import (
	"flag"
	"fmt"
	"log"
)

// TODO: make configurable
var inputHeader = []string{
	"num",
	"date",
	"time",
	"orig",
	"type",
	"i/f_name",
	"i/f_dir",
	"src",
	"dst",
	"proto",
	"appi_name",
	"proxy_src_ip",
	"Modbus_Function_Code",
	"Modbus_Function_Description",
	"Modbus_Transaction_ID",
	"SCADA_Tag",
	"Modbus_Value",
	"service",
	"s_port",
	"Tag",
	//"Normal/Attack",
}
var inputHeaderLen = len(inputHeader)

// TODO: make configurable
var outputHeader = []string{
	"unixtime",
	"orig",
	"type",
	"i/f_name",
	"i/f_dir",
	"src",
	"dst",
	"proto",
	"appi_name",
	"proxy_src_ip",
	"modbus_function_code",
	"modbus_function_description",
	"modbus_transaction_id",
	"scada_tag",
	"modbus_value",
	"service",
	"s_port",
	"classification",
}
var outputHeaderLen = len(outputHeader)

/*
 * Globals
 */

const version = "v0.3.1"

var (
	// stats about applied labels
	hitMap     = make(map[string]int)
	hitMapLock sync.Mutex

	// attack information for mapping
	attacks []*attack

	// worker pool
	workers []chan task
	next    int

	results     = make(map[string]*fileSummary)
	resultMutex sync.Mutex

	colSums map[string]*encoder.ColumnSummary
)

/*
 * Main
 */

func main() {

	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		return
	}

	if *flagOut != "." {
		if _, err := os.Stat(*flagOut); err != nil {
			// ensure the directory exists
			os.MkdirAll(*flagOut, 0700)
		}
	}

	if *flagAttackList != "" {
		attacks = parseAttackList(*flagAttackList)
	}

	var (
		files      []string
		start      = time.Now()
		wg         sync.WaitGroup
		fileFilter []string
	)

	if *flagFileFilter != "" {
		c, err := ioutil.ReadFile(*flagFileFilter)
		if err != nil {
			log.Fatal(err)
		}
		fileFilter = strings.Split(string(c), "\n")
	}

	err := filepath.Walk(*flagInput, func(path string, info os.FileInfo, err error) error {

		if strings.HasSuffix(path, *flagPathSuffix) {
			if len(fileFilter) != 0 {
				if contains(fileFilter, path) {
					files = append(files, path)
				}
			} else {
				files = append(files, path)
			}
		}
		if *flagMaxFiles != 0 {
			if len(files) == *flagMaxFiles {
				return filepath.SkipDir
			}
		}

		return nil
	})
	if err != nil {
		panic(err)
	}

	totalFiles := len(files)
	fmt.Println("started at", time.Now())
	fmt.Println("collected", totalFiles, "CSV files for labeling, num workers:", *flagNumWorkers)
	fmt.Println("offset", *flagOffset)
	fmt.Println("new CSV header:", outputHeader)
	fmt.Println("file_suffix", *flagPathSuffix)
	fmt.Println("output directory:", *flagOut)
	fmt.Println("initializing", *flagNumWorkers, "workers")

	// validate offset arg
	if *flagOffset >= totalFiles || *flagOffset < 0 {
		log.Fatal("invalid value for file offset")
	}

	// spawn workers
	for i := 0; i < *flagNumWorkers; i++ {
		workers = append(workers, worker())
	}

	// set max files
	if *flagMaxFiles == 0 {
		*flagMaxFiles = len(files)
	}

	if *flagColumnSummaries != "" {

		data, err := ioutil.ReadFile(*flagColumnSummaries)
		if err != nil {
			log.Fatal(err)
		}

		err = json.Unmarshal(data, &colSums)
		if err != nil {
			log.Fatal("failed to unmarshal json", err)
		}

		fmt.Println("loaded column summaries:", len(colSums))

		runLabeling(files, &wg, totalFiles)
		fmt.Println("done in", time.Since(start))
		return
	}

	// analyze task
	for current, file := range files[*flagOffset:*flagMaxFiles] {
		wg.Add(1)
		handleTask(task{
			typ:        typeAnalyze,
			file:       file,
			current:    current,
			totalFiles: totalFiles,
			wg:         &wg,
		})
	}

	fmt.Println("started all analysis jobs, waiting...")
	wg.Wait()

	printAnalysisInfo()

	if *flagAnalyzeOnly {
		fmt.Println("done in", time.Since(start))
		return
	}

	// run labeling
	runLabeling(files, &wg, totalFiles)
	fmt.Println("done in", time.Since(start))
}
