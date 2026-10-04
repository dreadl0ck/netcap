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
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

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

// BuildVulnDB builds netcap.sqlite in outDir from the NVD 2.0 yearly feeds
// (nvdcve-2.0-<year>.json.gz) and files_exploits.csv found in buildPath.
// Missing years and a missing exploit CSV are logged and skipped; a build
// without a single NVD entry is an error, so a failed download never
// replaces a good database.
func BuildVulnDB(buildPath, outDir string, nvdStart int, verbose bool) error {
	start := time.Now()
	out := filepath.Join(outDir, vulndb.FileName)

	b, err := vulndb.Create(out)
	if err != nil {
		return err
	}

	b.SetMeta("built_at", start.UTC().Format(time.RFC3339))
	b.SetMeta("nvd_start_year", strconv.Itoa(nvdStart))

	for _, year := range yearRange(nvdStart, time.Now().Year()) {
		file := filepath.Join(buildPath, "nvdcve-2.0-"+year+".json.gz")
		n, errYear := indexNVDFile(b, file)
		if errYear != nil {
			if errors.Is(errYear, os.ErrNotExist) {
				log.Printf("WARNING: NVD feed for %s missing: %s", year, file)
				continue
			}
			b.Abort()
			return fmt.Errorf("NVD feed %s: %w", file, errYear)
		}
		if verbose {
			fmt.Println("indexed NVD year", year, "entries:", n)
		}
	}

	if errExploits := indexExploitCSV(b, filepath.Join(buildPath, "files_exploits.csv")); errExploits != nil {
		if !errors.Is(errExploits, os.ErrNotExist) {
			b.Abort()
			return errExploits
		}
		log.Printf("WARNING: exploit-db CSV missing, building without exploits")
	}

	nvdCount, exploitCount := b.Counts()
	if nvdCount == 0 {
		b.Abort()
		return fmt.Errorf("no NVD entries found in %s", buildPath)
	}

	if err = b.Finish(); err != nil {
		return err
	}

	size := "?"
	if stat, errStat := os.Stat(out); errStat == nil {
		size = humanize.Bytes(uint64(stat.Size()))
	}

	fmt.Printf("built %s: %d NVD entries, %d exploits, %s in %v\n", out, nvdCount, exploitCount, size, time.Since(start))

	return nil
}

// indexNVDFile streams one gzipped NVD 2.0 feed into b.
func indexNVDFile(b *vulndb.Builder, file string) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}

	dec := json.NewDecoder(r)
	// Walk to the "vulnerabilities" array, then decode one element at a time
	// instead of holding a whole year (up to ~1 GB of JSON) in memory.
	if err = seekArray(dec, "vulnerabilities"); err != nil {
		return 0, err
	}

	var count int

	for dec.More() {
		var item nvdItem
		if err = dec.Decode(&item); err != nil {
			return count, err
		}

		if v, ok := vulnerabilityFromNVD(&item); ok {
			if err = b.AddVulnerability(v); err != nil {
				return count, err
			}
			count++
		}
	}

	return count, nil
}

// seekArray advances dec past the opening bracket of the top-level array
// stored under key.
func seekArray(dec *json.Decoder, key string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("NVD feed is not a JSON object")
	}

	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return err
		}
		if tok == key {
			tok, err = dec.Token()
			if err != nil {
				return err
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				return fmt.Errorf("%s is not an array", key)
			}
			return nil
		}
		// skip the value of any other key
		var skip json.RawMessage
		if err = dec.Decode(&skip); err != nil {
			return err
		}
	}

	return fmt.Errorf("key %s not found", key)
}

// vulnerabilityFromNVD maps an NVD 2.0 item to a vulnerability; items
// without an English description are skipped.
func vulnerabilityFromNVD(item *nvdItem) (vulndb.Vulnerability, bool) {
	cve := &item.Cve

	var description string

	for _, entry := range cve.Descriptions {
		if entry.Lang == "en" {
			description = entry.Value
			break
		}
	}

	if description == "" {
		return vulndb.Vulnerability{}, false
	}

	var versions []string

	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			if node.Operator != "OR" {
				continue
			}

			for _, cpe := range node.CpeMatch {
				if !cpe.Vulnerable {
					continue
				}

				if cpe.VersionStartIncluding != "" {
					versions = append(versions, cpe.VersionStartIncluding)

					// generate array of intermediate versions if end is set
					if cpe.VersionEndExcluding != "" {
						versions = append(versions, intermediatePatchVersions(cpe.VersionStartIncluding, cpe.VersionEndExcluding)...)
					}

					continue
				}

				// CPE format: cpe:2.3:part:vendor:product:version:...
				parts := strings.Split(cpe.Criteria, ":")
				if len(parts) > 5 && parts[5] != "*" && parts[5] != "-" {
					versions = append(versions, parts[5])
				}
			}
		}
	}

	// If no versions found, try to extract from description
	if len(versions) == 0 {
		if genRes := reSimpleVersion.FindString(description); genRes != "" {
			versions = append(versions, genRes)
		}
	}

	v := vulndb.Vulnerability{
		ID:          cve.ID,
		Description: description,
		Versions:    versions,
	}

	if len(cve.Metrics.CvssMetricV2) > 0 {
		metric := cve.Metrics.CvssMetricV2[0]
		v.BaseSeverity = metric.BaseSeverity
		v.Severity = metric.BaseSeverity
		v.V2Score = strconv.FormatFloat(metric.CvssData.BaseScore, 'f', 1, 64)
		v.BaseScore = metric.CvssData.BaseScore
		v.AccessVector = metric.CvssData.AccessVector
		v.AttackComplexity = metric.CvssData.AccessComplexity
		v.ConfidentialityImpact = metric.CvssData.ConfidentialityImpact
		v.IntegrityImpact = metric.CvssData.IntegrityImpact
		v.AvailabilityImpact = metric.CvssData.AvailabilityImpact
	}

	return v, true
}

// indexExploitCSV adds every row of exploit-db's files_exploits.csv to b.
func indexExploitCSV(b *vulndb.Builder, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("exploit-db CSV header: %w", err)
	}

	col := map[string]int{}
	for i, name := range header {
		col[name] = i
	}

	for _, name := range []string{"id", "file", "description"} {
		if _, ok := col[name]; !ok {
			return fmt.Errorf("exploit-db CSV lacks column %q", name)
		}
	}

	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}

	for {
		rec, errRead := r.Read()
		if errors.Is(errRead, io.EOF) {
			return nil
		}
		if errRead != nil {
			log.Printf("WARNING: skipping malformed exploit-db row: %v", errRead)
			continue
		}

		err = b.AddExploit(vulndb.Exploit{
			ID:          get(rec, "id"),
			File:        get(rec, "file"),
			Description: get(rec, "description"),
			Date:        get(rec, "date_published"),
			Author:      get(rec, "author"),
			Type:        get(rec, "type"),
			Platform:    get(rec, "platform"),
			Port:        get(rec, "port"),
		})
		if err != nil {
			return err
		}
	}
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
