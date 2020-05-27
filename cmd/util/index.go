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
	"regexp"
	"strconv"
	"strings"

	"time"

	"github.com/blevesearch/bleve"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/resolvers"
)

// TODO: can we use the protobuf from types package instead?
type Exploit struct {
	Id          string
	File        string
	Description string
	Date        string
	Author      string
	Typ         string
	Platform    string
	Port        string
}

// TODO: can we use the protobuf from types package instead?
type Vulnerability struct {
	Id                    string
	Description           string
	Severity              string
	V2Score               string
	AccessVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	Scope                 string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	BaseScore             float64
	BaseSeverity          string
	Versions              []string
}

// used to fetch version identifier from description string from NVD item
// if cpe url does not contain version information
var reSimpleVersion = regexp.MustCompile(`([0-9]+)\.([0-9]+)\.?([0-9]*)?`)

func intermediatePatchVersions(from string, until string) []string {

	var out []string

	parts := strings.Split(from, ".")
	patch, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return nil
	}

	untilParts := strings.Split(until, ".")
	untilInt, err := strconv.Atoi(untilParts[len(untilParts)-1])
	if err != nil {
		return nil
	}

	for i := patch; i < untilInt; i++ {
		patch++
		if patch == untilInt {
			break
		}
		parts[len(parts)-1] = strconv.Itoa(patch)
		out = append(out, strings.Join(parts, "."))
	}

	return out
}

func indexData(in string) {

	var (
		start     = time.Now()
		indexPath string
		index     bleve.Index
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
		err = file.Close()
		if err != nil {
			log.Fatal(err)
		}

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
		err = file.Close()
		if err != nil {
			log.Fatal(err)
		}

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
				File:        rec[1],
				Description: rec[2],
				Date:        rec[3],
				Author:      rec[4],
				Typ:         rec[5],
				Platform:    rec[6],
				Port:        rec[7],
			}
			err = index.Index(e.Id, e)
			if err != nil {
				fmt.Println(err)
			}
		}

		fmt.Println("indexed exploit DB, num entries:", count)

	case "nvd":

		indexPath = filepath.Join(resolvers.DataBaseSource, "nvd-v2.bleve")
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

				for _, entry := range v.Cve.Description.DescriptionData {
					if entry.Lang == "en" {

						var versions []string
						for _, n := range v.Configurations.Nodes {
							if n.Operator == "OR" {
								for _, cpe := range n.CpeMatch {
									if cpe.Vulnerable {

										if cpe.VersionStartIncluding != "" {
											versions = append(versions, cpe.VersionStartIncluding)

											// generate array of intermediate versions if end is set
											if cpe.VersionEndExcluding != "" {
												versions = append(versions, intermediatePatchVersions(cpe.VersionStartIncluding, cpe.VersionEndExcluding)...)
											}
										} else {

											// try to get version from cpeURI
											parts := strings.Split(cpe.Cpe23URI, ":")
											if len(parts) > 5 {
												v := parts[5]
												if v != "*" && v != "-" {
													versions = append(versions, v)
												}
											}
										}
									}
								}
							}
						}
						if len(versions) == 0 {
							genRes := reSimpleVersion.FindString(entry.Value)
							if genRes != "" {
								versions = append(versions, genRes)
							}
						}
						//fmt.Println(" ", v.Cve.CVEDataMeta.ID, entry.Value, " =>", versions)

						e := Vulnerability{
							Id:                    v.Cve.CVEDataMeta.ID,
							Description:           entry.Value,
							Severity:              v.Impact.BaseMetricV2.Severity,
							V2Score:               strconv.FormatFloat(v.Impact.BaseMetricV2.CvssV2.BaseScore, 'f', 1, 64),
							AccessVector:          v.Impact.BaseMetricV2.CvssV2.AccessVector,
							AttackComplexity:      v.Impact.BaseMetricV3.CvssV3.AttackComplexity,
							PrivilegesRequired:    v.Impact.BaseMetricV3.CvssV3.PrivilegesRequired,
							UserInteraction:       v.Impact.BaseMetricV3.CvssV3.UserInteraction,
							Scope:                 v.Impact.BaseMetricV3.CvssV3.Scope,
							ConfidentialityImpact: v.Impact.BaseMetricV3.CvssV3.ConfidentialityImpact,
							IntegrityImpact:       v.Impact.BaseMetricV3.CvssV3.IntegrityImpact,
							AvailabilityImpact:    v.Impact.BaseMetricV3.CvssV3.AvailabilityImpact,
							BaseScore:             v.Impact.BaseMetricV3.CvssV3.BaseScore,
							BaseSeverity:          v.Impact.BaseMetricV3.CvssV3.BaseSeverity,
							Versions:              versions,
						}
						err = index.Index(e.Id, e)
						if err != nil {
							fmt.Println(err)
						}
						break
					}
				}
			}
			fmt.Println()
		}

		fmt.Println("loaded", total, "NVD CVEs in", time.Since(start))
	default:
		log.Fatal("Could not handle given file", *flagIndex)
	}

	// retrieve size of the underlying boltdb
	stat, err := os.Stat(filepath.Join(indexPath, "store"))
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
