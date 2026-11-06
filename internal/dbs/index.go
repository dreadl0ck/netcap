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
	"database/sql"
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

var reCVEReference = regexp.MustCompile(`(?i)CVE-[0-9]{4}-[0-9]{4,}`)

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

// BuildVulnDB builds current-schema SQLite from every required NVD year, without
// Exploit-DB input. Normalized metadata makes identical inputs reproducible.
// Only a completed, normalized database replaces a prior output.
func BuildVulnDB(buildPath, outDir string, nvdStart int, verbose bool) error {
	if nvdStart < 2002 || nvdStart > time.Now().Year() {
		return fmt.Errorf("invalid NVD start year %d", nvdStart)
	}
	start := time.Now()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	private, err := os.MkdirTemp(outDir, ".nvd-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(private)
	frozen := filepath.Join(private, "inputs")
	inputs, err := freezeNVDInputs(buildPath, frozen, nvdStart, start.Year())
	if err != nil {
		return err
	}
	out := filepath.Join(private, vulndb.FileName)

	b, err := vulndb.Create(out)
	if err != nil {
		return err
	}

	// Retain the schema-1 key without inventing a reproducible build time.
	// Archive creation time is recorded separately in release metadata.
	b.SetMeta("built_at", "")
	b.SetMeta("input_sha256", nvdInputDigest(inputs))
	inputJSON, err := json.Marshal(inputs)
	if err != nil {
		b.Abort()
		return err
	}
	b.SetMeta("nvd_inputs", string(inputJSON))
	b.SetMeta("nvd_end_year", strconv.Itoa(start.Year()))
	b.SetMeta("nvd_start_year", strconv.Itoa(nvdStart))
	b.SetMeta("publication_profile", "nvd-only-v3")

	for _, input := range inputs {
		year := strconv.Itoa(input.Year)
		file := filepath.Join(frozen, "nvdcve-2.0-"+year+".json.gz")
		n, errYear := indexNVDFile(b, file)
		if errYear != nil {
			b.Abort()
			return fmt.Errorf("NVD feed %s: %w", file, errYear)
		}
		sum, size, err := hashFile(file)
		if err != nil || sum != input.SHA256 || size != input.Size {
			b.Abort()
			return fmt.Errorf("frozen NVD year %s changed during indexing", year)
		}
		if verbose {
			fmt.Println("indexed NVD year", year, "entries:", n)
		}
	}

	nvdCount, exploitCount := b.Counts()
	if nvdCount == 0 {
		b.Abort()
		return fmt.Errorf("no NVD entries found in %s", buildPath)
	}

	if err = b.Finish(); err != nil {
		return err
	}
	if err := normalizeSQLiteMeta(out); err != nil {
		return err
	}
	if err := os.Rename(out, filepath.Join(outDir, vulndb.FileName)); err != nil {
		return err
	}

	size := "?"
	if stat, errStat := os.Stat(filepath.Join(outDir, vulndb.FileName)); errStat == nil {
		size = humanize.Bytes(uint64(stat.Size()))
	}

	fmt.Printf("built %s: %d NVD entries, %d exploits, %s in %v\n", out, nvdCount, exploitCount, size, time.Since(start))

	return nil
}

func normalizeSQLiteMeta(path string) error {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	rows, err := conn.Query("SELECT key,value FROM meta ORDER BY key")
	if err != nil {
		return err
	}
	var values [][2]string
	for rows.Next() {
		var v [2]string
		if err := rows.Scan(&v[0], &v[1]); err != nil {
			rows.Close()
			return err
		}
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM meta"); err != nil {
		return err
	}
	for _, v := range values {
		if _, err := tx.Exec("INSERT INTO meta (key,value) VALUES (?,?)", v[0], v[1]); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if _, err := conn.Exec("VACUUM"); err != nil {
		return err
	}
	return conn.Close()
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
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return count, fmt.Errorf("truncated NVD array: %v", err)
	}
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return count, err
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return count, err
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return count, fmt.Errorf("truncated NVD object: %v", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return count, fmt.Errorf("trailing or corrupt NVD data: %v", err)
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return count, err
	}
	if err := r.Close(); err != nil {
		return count, err
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

			for _, cpe := range node.Matches {
				if !cpe.Vulnerable {
					continue
				}

				if cpe.StartIncluding != "" {
					versions = append(versions, cpe.StartIncluding)

					// generate array of intermediate versions if end is set
					if cpe.EndExcluding != "" {
						versions = append(versions, intermediatePatchVersions(cpe.StartIncluding, cpe.EndExcluding)...)
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
		ID:             cve.ID,
		Description:    description,
		Versions:       versions,
		Configurations: cve.Configurations,
	}
	for _, ref := range cve.References {
		v.References = append(v.References, vulndb.Reference{URL: ref.URL, Source: ref.Source, Tags: ref.Tags})
	}
	v.References = vulndb.NormalizeReferences(v.References)

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
			CVEs:        reCVEReference.FindAllString(strings.ToUpper(get(rec, "codes")), -1),
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
	if start > end {
		return nil
	}
	var out []string
	for i := start; i <= end; i++ {
		out = append(out, strconv.Itoa(i))
	}
	return out
}
