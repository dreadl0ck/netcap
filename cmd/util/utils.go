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
	fmt.Println("	$ net util -clone-dbs")
	fmt.Println()
}

// usage prints the use.
func printUsage() {
	printHeader()
	fs.PrintDefaults()
}

// CheckFields checks if the separator occurs inside fields of audit records
// to prevent this breaking the generated CSV file.
func checkFields() {
	r, err := io.Open(*flagInput, *flagMemBufferSize)
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
					for i := 0; i < numStructFields; i++ {
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
			for i := 0; i < numStructFields; i++ {
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
	out, err := exec.Command("net.capture", "-r", *flagInput).Output()
	if err != nil {
		panic(err)
	}

	// iterate over lines
	for _, line := range strings.Split(string(out), "\n") {
		count := strings.Count(line, *flagSeparator)
		if count != numExpectedFields-1 {
			fmt.Println(strings.Replace(line, *flagSeparator, ansi.Red+*flagSeparator+ansi.Reset, -1), ansi.Red, count, ansi.Reset)
		}
	}
}
