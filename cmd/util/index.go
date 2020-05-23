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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"io"
	"io/ioutil"
	"log"
	"net/textproto"
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

	var (
		start = time.Now()
		indexPath string
		index bleve.Index
	)

	switch in {
	case "mitre-cve":
		indexPath = filepath.Join(resolvers.DataBaseSource, "mitre-cve.bleve")
		fmt.Println("index path", indexPath)

		if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexPath) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexPath) // To create a new index
		}

		// wget https://cve.mitre.org/data/downloads/allitems.csv
		file, err := os.Open(filepath.Join(resolvers.DataBaseSource, "allitems.csv"))
		if err != nil {
			log.Fatal(err)
		}

		// count total number of lines
		tr := textproto.NewReader(bufio.NewReader(file))
		var total int
		for {
			line, err := tr.ReadLine()
			if err == io.EOF {
				break
			}
			if !strings.HasPrefix(line, "#") {
				total++
			}
		}
		file.Close()

		// reopen file handle
		file, err = os.Open(filepath.Join(resolvers.DataBaseSource, "files_exploits.csv"))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		r := csv.NewReader(file)
		var count int
		for {
			rec, err := r.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				fmt.Println(err, rec)
				continue
			}
			count++
			utils.ClearLine()
			fmt.Print("processing: ", count, " / ", total)
			e := Exploit{
				Id:          rec[0],
				Status:      rec[1],
				Description: rec[2],
			}
			err = index.Index(e.Id, e)
			if err != nil {
				fmt.Println(err, r)
			}
		}

		fmt.Println("indexed mitre DB, num entries:", count)

	case "exploit-db":

		indexPath = filepath.Join(resolvers.DataBaseSource, "exploit-db.bleve")
		fmt.Println("index path", indexPath)

		if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexPath) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexPath) // To create a new index
		}

		// wget https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv
		file, err := os.Open(filepath.Join(resolvers.DataBaseSource, "files_exploits.csv"))
		if err != nil {
			log.Fatal(err)
		}

		// count total number of lines
		tr := textproto.NewReader(bufio.NewReader(file))
		var total int
		for {
			line, err := tr.ReadLine()
			if err == io.EOF {
				break
			}
			if !strings.HasPrefix(line, "#") {
				total++
			}
		}
		file.Close()

		// reopen file handle
		file, err = os.Open(filepath.Join(resolvers.DataBaseSource, "files_exploits.csv"))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		r := csv.NewReader(file)
		var count int
		for {
			rec, err := r.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				fmt.Println(err, rec)
				continue
			}
			count++
			utils.ClearLine()
			fmt.Print("processing: ", count, " / ", total)
			e := Exploit{
				Id:          rec[0],
				Status:      rec[1],
				Description: rec[2],
			}
			err = index.Index(e.Id, e)
			if err != nil {
				fmt.Println(err)
			}
		}

		fmt.Println("indexed exploit DB, num entries:", count)

	case "nvd":

		indexPath = filepath.Join(resolvers.DataBaseSource, "cve.bleve.nvd")
		fmt.Println("index path", indexPath)

		if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexPath) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexPath) // To create a new index
		}
		var (
			start = time.Now()
			years = []string{
				"2002",
				"2003",
				"2004",
				"2005",
				"2006",
				"2007",
				"2008",
				"2009",
				"2010",
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
				err = index.Index(v.Cve.CVEDataMeta.ID, v)
				if err != nil {
					fmt.Println(err)
				}
			}
			fmt.Println()
		}

		fmt.Println("loaded", total, "NVD CVEs in", time.Since(start))
	default:
		log.Fatal("Could not handle given file", *flagIndex)
	}

	stat, err := os.Stat(indexPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("done in", time.Since(start), "index size", humanize.Bytes(uint64(stat.Size())), "path", indexPath)
}

func makeBleveIndex(indexName string) bleve.Index {
	mapping := bleve.NewIndexMapping()
	index, err := bleve.New(indexName, mapping)
	if err != nil {
		log.Fatalln("failed to create index:", err)
	}
	return index
}
