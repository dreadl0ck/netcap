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
	"fmt"
	"github.com/dreadl0ck/netcap/encoder"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/mgutz/ansi"
	"gonum.org/v1/gonum/stat"
)

// TODO: make configurable
var stringColumns = map[string]bool{
	"SCADA_Tag":                   true,
	"type":                        true,
	"orig":                        true,
	"Modbus_Value":                true,
	"proxy_src_ip":                true,
	"proto":                       true,
	"src":                         true,
	"i/f_name":                    true,
	"Modbus_Function_Description": true,
	"appi_name":                   true,
	"i/f_dir":                     true,
	"Normal/Attack":               true,
	"dst":                         true,
}

func merge(results map[string]*fileSummary) map[string]*encoder.ColumnSummary {

	if *flagCountAttacks {
		var attackFiles sort.StringSlice

		for _, sum := range results {
			if sum.attacks != 0 {
				attackFiles = append(attackFiles, sum.file)
			}
		}

		attackFiles.Sort()

		for _, file := range attackFiles {
			sum := results[file]
			var uniqueAttacks []string
			for a := range sum.uniqueAttacks {
				uniqueAttacks = append(uniqueAttacks, a)
			}
			fmt.Println(file, ":", sum.attacks, uniqueAttacks)
		}
		return nil
	}

	d := &datasetSummary{
		strings: make(map[string]map[string]int),
	}

	// init columns map
	for _, sum := range results {
		for col, _ := range sum.strings {
			d.strings[col] = make(map[string]int)
		}
		break
	}

	var skipped int

	// merge results
	for _, sum := range results {

		//fmt.Println(file, sum)
		skipped += sum.skipped

		d.fileCount++
		d.lineCount += sum.lineCount
		d.columns = sum.columns

		if *flagDebug {
			fmt.Println(ansi.Red+sum.file, "len(sum.columns):", len(sum.columns), "len(sum.strings):", len(sum.strings), ansi.Reset)
			time.Sleep(1 * time.Second)
		}

		for col, values := range sum.strings {
			if *flagDebug {
				fmt.Println("column:", col, sum.file, sum.columns, len(sum.columns))
			}
			for key, num := range values {
				d.strings[col][key] += num
			}
		}
	}

	fmt.Println(ansi.Red + "DONE")
	fmt.Println("files:", d.fileCount)
	fmt.Println("lines:", d.lineCount)
	fmt.Println("columns", d.columns, ansi.Reset)
	//spew.Dump(d)

	var colSums = make(map[string]*encoder.ColumnSummary)

	for col, data := range d.strings {
		fmt.Println(ansi.Yellow, "> column:", col, "unique_values:", len(data), ansi.Reset)

		// lookup type for column
		isString := stringColumns[col]

		if isString {

			// TODO: use new map instead of string array
			var unique []string
			for value := range data {
				unique = append(unique, value)
			}
			length := len(unique)

			if col != "Modbus_Value" && col != "time" {
				for _, v := range unique {
					fmt.Println("   -", v)
				}
			}

			values := makeIntSlice(length)
			mean, std := stat.MeanStdDev(values, nil)
			fmt.Println(col, "mean:", mean, "stddev:", std)

			colSums[col] = &encoder.ColumnSummary{
				UniqueStrings: map[string]float64{},
				Version:       version,
				Col:           col,
				Typ:           encoder.TypeString,
				Mean:          mean,
				Std:           std,
				Min:           math.MaxFloat64,
				Max:           float64(length) - 1,
			}
		} else {

			var values []float64

			// create series over all data points
			for value, num := range data {

				v, err := strconv.ParseFloat(value, 64)
				if err != nil {
					fmt.Println("failed to parse float in col "+col+", error: ", err, value)
					continue
				}

				for i := 0; i < num; i++ {
					values = append(values, v)
				}
			}

			if col == "Tag" {
				fmt.Println(data)
			}

			mean, std := stat.MeanStdDev(values, nil)
			fmt.Println(col, "mean:", mean, "stddev:", std)

			min, max := encoder.MinMaxIntArr(values)

			colSums[col] = &encoder.ColumnSummary{
				UniqueStrings: map[string]float64{},
				Version:       version,
				Col:           col,
				Typ:           encoder.TypeNumeric,
				Mean:          mean,
				Std:           std,
				Min:           min,
				Max:           max,
			}
		}
	}

	fmt.Println("skipped lines with missing values:", skipped)

	return colSums
}
