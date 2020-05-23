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

package util

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/dreadl0ck/netcap/utils"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blevesearch/bleve"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
)

type Exploit struct {
	Id          string
	Status      string
	Description string
}

func indexData(in string) {

	start := time.Now()

	if strings.Contains(in, ".csv") {

		indexName := filepath.Join(resolvers.DataBaseSource, "cve.bleve.mitre")
		var index bleve.Index
		if _, err := os.Stat(indexName); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexName) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexName) // To create a new index
		}

		file, err := os.Open(filepath.Join(resolvers.DataBaseSource, in))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			lineSlice := strings.Split(line, ",")
			lineExploit := Exploit{
				Id:          lineSlice[0],
				Status:      lineSlice[1],
				Description: lineSlice[2],
			}
			index.Index(lineExploit.Id, lineExploit)
		}

		fmt.Println("Loaded DB")

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else if strings.Contains(in, ".json") {

		var (
			indexName = filepath.Join(resolvers.DataBaseSource, "cve.bleve.nvd")
			index bleve.Index
		)

		fmt.Println("index path", indexName)

		if _, err := os.Stat(indexName); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexName) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexName) // To create a new index
		}
		var (
			start = time.Now()
			years = []string{
				//"2002",
				//"2003",
				//"2004",
				//"2005",
				//"2006",
				//"2007",
				//"2008",
				//"2009",
				//"2010",
				"2011",
				"2012",
				"2013",
				"2014",
				"2015",
				"2016",
				"2017",
				"2018",
				"2019",
				"2020",
			}
			total int
		)
		for _, year := range years {
			fmt.Print("processing files for year ", year)
			data, err := ioutil.ReadFile(filepath.Join(resolvers.DataBaseSource, "nvdcve-1.1-"+year+".json"))
			if err != nil {
				log.Fatal("Could not open file " + filepath.Join(resolvers.DataBaseSource, "nvdcve-1.1-"+year+".json"))
			}

			var items = new(encoder.NVDVulnerabilityItems)
			err = json.Unmarshal(data, items)
			total += len(items.CVEItems)
			length := len(items.CVEItems)
			for i, v := range items.CVEItems {
				utils.ClearLine()
				fmt.Print("processing files for year ", year, ": ", i, " / ", length)
				index.Index(v.Cve.CVEDataMeta.ID, v)
			}
			fmt.Println()
		}

		//spew.Dump(items)
		fmt.Println("loaded", total, "CVEs in", time.Since(start))
	} else {
		log.Fatal("Could not handle given file", *flagIndex)
	}

	fmt.Println("done in", time.Since(start))
}

func makeBleveIndex(indexName string) bleve.Index {
	mapping := bleve.NewIndexMapping()
	index, err := bleve.New(indexName, mapping)
	if err != nil {
		log.Fatalln("Trouble making index!")
	}
	return index
}
