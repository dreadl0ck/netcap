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

package dbs

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/utils"
)

// exploit models information about a software exploit.
// TODO: can we use the protobuf from types package instead?
type exploit struct {
	ID          string
	File        string
	Description string
	Date        string
	Author      string
	Typ         string
	Platform    string
	Port        string
}

// vulnerability models information about a software Vulnerability.
// TODO: can we use the protobuf from types package instead?
type vulnerability struct {
	ID                    string
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
// if cpe url does not contain version information.
var reSimpleVersion = regexp.MustCompile(`([0-9]+)\.([0-9]+)\.?([0-9]*)?`)

// generates max 20 intermediate versions
// until is excluded.
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

	if patch >= untilInt {
		// nothing to do
		return nil
	}

	var numRounds int

	for i := patch; i < untilInt; i++ {
		patch++
		numRounds++

		if patch == untilInt || numRounds > 20 {
			break
		}

		parts[len(parts)-1] = strconv.Itoa(patch)
		out = append(out, strings.Join(parts, "."))
	}

	return out
}

// IndexData will index the data into a bleve database for full text search
func IndexData(in string, out string, buildPath string, nvdIndexStart int, verbose bool) {
	var (
		start     = time.Now()
		indexPath string
		index     bleve.Index
	)

	switch in {
	// nolint
	case "mitre-cve":
		indexPath = filepath.Join(out, "mitre-cve.bleve")
		fmt.Println("index path", indexPath)

		if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexPath) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexPath) // To create a new index
		}

		// wget https://cve.mitre.org/data/downloads/allitems.csv
		file, err := os.Open(filepath.Join(buildPath, "mitre", "allitems.csv"))
		if err != nil {
			log.Fatal(err)
		}

		var (
			// count total number of lines
			total int
			tr    = textproto.NewReader(bufio.NewReader(file))
			line  string
		)

		for {
			line, err = tr.ReadLine()
			if errors.Is(err, io.EOF) {
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
		file, err = os.Open(filepath.Join(buildPath, "exploitdb", "files_exploits.csv"))
		if err != nil {
			log.Fatal(err)
		}

		defer func() {
			errClose := file.Close()
			if errClose != nil && !errors.Is(errClose, io.EOF) {
				fmt.Println("failed to close:", errClose)
			}
		}()

		var (
			r     = csv.NewReader(file)
			count int
			rec   []string
		)
		for {
			rec, err = r.Read()
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				fmt.Println(err, rec)
				continue
			}
			count++

			if verbose {
				utils.ClearLine()
				fmt.Print("processing: ", count, " / ", total)
			}

			e := exploit{
				ID:          rec[0],
				Description: rec[2],
			}

			err = index.Index(e.ID, e)
			if err != nil {
				fmt.Println(err, r)
			}
		}

		fmt.Println("indexed mitre DB, num entries:", count)

	case "exploit-db":
		indexPath = filepath.Join(out, "exploit-db.bleve")
		fmt.Println("index path", indexPath)

		if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
			index, err = bleve.Open(indexPath) // To search or update an existing index
			if err != nil {
				fmt.Println(err)
			}
		} else {
			index = makeBleveIndex(indexPath) // To create a new index
		}

		// wget https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv
		file, err := os.Open(filepath.Join(buildPath, "files_exploits.csv"))
		if err != nil {
			log.Fatal(err)
		}

		// count total number of lines
		var (
			tr    = textproto.NewReader(bufio.NewReader(file))
			total int
			line  string
		)

		for {
			line, err = tr.ReadLine()
			if errors.Is(err, io.EOF) {
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
		file, err = os.Open(filepath.Join(buildPath, "files_exploits.csv"))
		if err != nil {
			log.Fatal(err)
		}

		defer func() {
			errClose := file.Close()
			if errClose != nil && !errors.Is(errClose, io.EOF) {
				fmt.Println("failed to close:", errClose)
			}
		}()

		var (
			r     = csv.NewReader(file)
			count int
			rec   []string
		)

		for {
			rec, err = r.Read()
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				fmt.Println(err, rec)

				continue
			}
			count++

			if verbose {
				utils.ClearLine()
				fmt.Print("processing: ", count, " / ", total)
			}

			e := exploit{
				ID:          rec[0],
				File:        rec[1],
				Description: rec[2],
				Date:        rec[3],
				Author:      rec[4],
				Typ:         rec[5],
				Platform:    rec[6],
				Port:        rec[7],
			}

			err = index.Index(e.ID, e)
			if err != nil {
				fmt.Println(err)
			}
		}

		fmt.Println("indexed exploit DB, num entries:", count)

	case "nvd":
		indexPath = filepath.Join(out, "nvd.bleve")
		fmt.Println("index path", indexPath)

		if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
			index, _ = bleve.Open(indexPath) // To search or update an existing index
		} else {
			index = makeBleveIndex(indexPath) // To create a new index
		}

		defer func() {
			errClose := index.Close()
			if errClose != nil && !errors.Is(errClose, io.EOF) {
				fmt.Println("failed to close:", errClose)
			}
		}()

		var (
			years = yearRange(nvdIndexStart, time.Now().Year())
			total int
		)

		for _, year := range years {
			if verbose {
				fmt.Print("processing NVD items for year ", year)
			} else {
				fmt.Println("processing NVD items for year ", year)
			}
			file := filepath.Join(buildPath, "nvdcve-2.0-"+year+".json.gz")

			f, err := os.Open(file)
			if err != nil {
				log.Fatal(err)
			}

			r, err := gzip.NewReader(f)
			if err != nil {
				log.Fatal(err)
			}

			data, err := ioutil.ReadAll(r)
			if err != nil {
				log.Fatal("Could not read file " + file)
			}

			items := new(NVD2)

			err = json.Unmarshal(data, items)
			if err != nil {
				log.Fatal("failed to unmarshal CVE items for file"+file, err)
			}

			total += len(items.Vulnerabilities)
			length := len(items.Vulnerabilities)

			for i, v := range items.Vulnerabilities {

				if verbose {
					utils.ClearLine()
					fmt.Print("processing files for year ", year, ": ", i, " / ", length)
				}

				// Find English description
				for _, entry := range v.Cve.Descriptions {
					if entry.Lang == "en" {

						var versions []string
						// Extract versions from configurations
						for _, config := range v.Cve.Configurations {
							for _, node := range config.Nodes {
								if node.Operator == "OR" {
									for _, cpe := range node.CpeMatch {
										if cpe.Vulnerable {
											if cpe.VersionStartIncluding != "" {
												versions = append(versions, cpe.VersionStartIncluding)

												// generate array of intermediate versions if end is set
												if cpe.VersionEndExcluding != "" {
													patchVersions := intermediatePatchVersions(cpe.VersionStartIncluding, cpe.VersionEndExcluding)
													if patchVersions != nil {
														versions = append(versions, patchVersions...)
													}
												}
											} else {
												// try to get version from CPE criteria
												// CPE format: cpe:2.3:part:vendor:product:version:...
												parts := strings.Split(cpe.Criteria, ":")
												if len(parts) > 5 {
													ver := parts[5]
													if ver != "*" && ver != "-" {
														versions = append(versions, ver)
													}
												}
											}
										}
									}
								}
							}
						}

						// If no versions found, try to extract from description
						if len(versions) == 0 {
							genRes := reSimpleVersion.FindString(entry.Value)
							if genRes != "" {
								versions = append(versions, genRes)
							}
						}

						// Extract CVSS v2 metrics if available
						var (
							severity              string
							v2Score               string
							accessVector          string
							baseScore             float64
							baseSeverity          string
							attackComplexity      string
							confidentialityImpact string
							integrityImpact       string
							availabilityImpact    string
						)

						if len(v.Cve.Metrics.CvssMetricV2) > 0 {
							metric := v.Cve.Metrics.CvssMetricV2[0]
							baseSeverity = metric.BaseSeverity
							severity = metric.BaseSeverity
							v2Score = strconv.FormatFloat(metric.CvssData.BaseScore, 'f', 1, 64)
							baseScore = metric.CvssData.BaseScore
							accessVector = metric.CvssData.AccessVector
							attackComplexity = metric.CvssData.AccessComplexity
							confidentialityImpact = metric.CvssData.ConfidentialityImpact
							integrityImpact = metric.CvssData.IntegrityImpact
							availabilityImpact = metric.CvssData.AvailabilityImpact
						}

						e := vulnerability{
							ID:                    v.Cve.ID,
							Description:           entry.Value,
							Severity:              severity,
							V2Score:               v2Score,
							AccessVector:          accessVector,
							AttackComplexity:      attackComplexity,
							PrivilegesRequired:    "", // Not available in v2
							UserInteraction:       "", // Not available in v2
							Scope:                 "", // Not available in v2
							ConfidentialityImpact: confidentialityImpact,
							IntegrityImpact:       integrityImpact,
							AvailabilityImpact:    availabilityImpact,
							BaseScore:             baseScore,
							BaseSeverity:          baseSeverity,
							Versions:              versions,
						}

						err = index.Index(e.ID, e)
						if err != nil {
							fmt.Println(err)
						}

						break
					}
				}
			}
			if verbose {
				// enforce a line break
				fmt.Println()
			} else {
				fmt.Println("finished indexing NVD items for year", year)
			}
		}

		fmt.Println("loaded", total, "NVD CVEs in", time.Since(start))
	default:
		log.Fatal("unknown keyword", in)
	}

	// retrieve size of the underlying boltdb
	stat, err := os.Stat(filepath.Join(indexPath, "store"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("done in", time.Since(start), "index size", humanize.Bytes(uint64(stat.Size())), "path", indexPath)
}

func yearRange(start int, end int) []string {
	if start >= end {
		log.Fatal("invalid range", start, "to", end)
	}
	var out []string
	for i := start; i <= end; i++ {
		out = append(out, strconv.Itoa(i))
	}
	return out
}

func makeBleveIndex(indexName string) bleve.Index {
	mapping := bleve.NewIndexMapping()

	index, err := bleve.New(indexName, mapping)
	if err != nil {
		log.Fatalln("failed to create index:", err)
	}

	return index
}
