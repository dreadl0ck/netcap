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

package util

import (
	"fmt"
	"log"
	"os/exec"
	"reflect"
	"strings"

	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("util tool usage examples:")
	fmt.Println("	$ net util -read TCP.ncap.gz -check")
	fmt.Println("	$ net util -read TCP.ncap.gz -check -sep '/'")
	fmt.Println("	$ net util -ts2utc 1505839354.197231")
	fmt.Println("	$ net util -download-geolite")
	fmt.Println("	$ net util -update-dbs")
	fmt.Println("	$ net util -gopacket-coverage")
	fmt.Println("	$ net util -decoders")
	fmt.Println()
}

// CheckFields checks if the separator occurs inside fields of audit records
// to prevent this breaking the generated CSV file.
func checkFields() {
	r, err := io.Open(currentCtx.String("read"), currentCtx.Int("membuf-size"))
	if err != nil {
		panic(err)
	}

	var (
		h, errFileHeader  = r.ReadHeader()
		record            = io.InitRecord(h.Type)
		numExpectedFields int
		checkFieldNames   = true
		allFieldNames     []string
	)
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}
	if p, ok := record.(types.AuditRecord); ok {
		numExpectedFields = len(p.CSVHeader())
		allFieldNames = p.CSVHeader()
	} else {
		fmt.Printf("type: %#v\n", record)
		log.Fatal("type does not implement the types.AuditRecord interface")
	}

	for {
		err = r.Next(record)
		if err != nil {
			fmt.Println(err)

			break
		}

		// check if field count is equal between fields from struct VS fields for CSV
		// and if all field names match
		// for the first audit record in the dumpfile
		if checkFieldNames {

			// set value to false, this code will only be executed for the first audit record in the file
			checkFieldNames = false

			var (
				// reflect to get value for audit record instance
				reflectedValue  = reflect.Indirect(reflect.ValueOf(record))
				numStructFields = reflectedValue.Type().NumField()
			)

			// check if field count matches
			if p, ok := record.(types.AuditRecord); ok {
				// bail out and print error if field count does not match
				if len(p.CSVRecord()) != numStructFields { // print all struct fields
					fmt.Println(h.Type.String() + " struct fields:")
					for i := range numStructFields {
						fmt.Println("- " + reflectedValue.Type().Field(i).Name)
					}

					// show CSV fields
					fmt.Println(h.Type.String() + " CSV fields:")
					for _, rec := range p.CSVHeader() {
						fmt.Println("- " + rec)
					}
					log.Fatal("[ERROR] number of fields differs for CSV and struct. CSV: ", len(p.CSVRecord()), ", struct: ", numStructFields)
				}
			}

			// check if all fields are in the right order and have the correct name
			for i := range numStructFields {
				if allFieldNames[i] != reflectedValue.Type().Field(i).Name {
					log.Fatal("[ERROR] different field names: ", allFieldNames[i], " and ", reflectedValue.Type().Field(i).Name)
				}
			}
		} else {
			// TODO refactor to use netcap lib to read file instead of calling it as command
			// to check all audit records for invalid number of separators
			break
		}
	}

	// close audit record file handle
	err = r.Close()
	if err != nil {
		log.Fatal("failed to close file: ", err)
	}

	// call netcap and parse output line by line
	// TODO refactor to use netcap lib to read file instead of calling it as command
	out, err := exec.Command("net.capture", "-r", currentCtx.String("read")).Output()
	if err != nil {
		panic(err)
	}

	flagSeparator := currentCtx.String("sep")

	// iterate over lines
	for line := range strings.SplitSeq(string(out), "\n") {
		count := strings.Count(line, flagSeparator)
		if count != numExpectedFields-1 {
			fmt.Println(strings.Replace(line, flagSeparator, ansi.Red+flagSeparator+ansi.Reset, -1), ansi.Red, count, ansi.Reset)
		}
	}
}
