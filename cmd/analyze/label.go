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
	"encoding/csv"
	"fmt"
	"github.com/dreadl0ck/netcap/encoder"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mgutz/ansi"
)

const precision = 10

// 1) correct fields
// 2) encode columns
// 3) add labels
func (t task) label() {

	info := "[" + strconv.Itoa(t.current+1) + "/" + strconv.Itoa(t.totalFiles) + "]"
	fmt.Println(info, "processing", t.file)

	inputFile, err := os.Open(t.file)
	if err != nil {
		log.Fatal(err)
	}
	defer inputFile.Close()

	var outFileName = strings.TrimSuffix(filepath.Base(t.file), ".csv") + "-labeled.csv"
	if *flagOut != "." {
		outFileName = filepath.Join(*flagOut, outFileName)
	}

	outputFile, err := os.Create(outFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	var (
		inputReader  = csv.NewReader(inputFile)
		outputWriter = csv.NewWriter(outputFile)
		numMatches   int
		count        int
		//skipped      int
	)
	if *flagReuseLineBuffer {
		inputReader.ReuseRecord = true
	}

	// write header
	err = outputWriter.Write(outputHeader)
	if err != nil {
		log.Fatal(err)
	}

	var (
		r []string
	)

	for {
		r, err = inputReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("error while reading next line from file", t.file, "error:", err, "length:", len(r), "expected:", len(inputHeader))
			fmt.Println(ansi.Red)
			for _, e := range r {
				fmt.Println("-" + e)
			}
			fmt.Println(ansi.Reset)
			count++
			continue
		}
		count++

		// skip header
		if count == 1 {
			// debug empty column in dataset
			if len(r) == 21 {
				if *flagDebug {
					fmt.Println(ansi.Red)
					fmt.Println(r)
					fmt.Println(ansi.Reset)
				}
			}
			continue
		}

		// if *flagSkipIncompleteRecords {
		// 	skip := false
		// 	for index, v := range r {
		// 		if v == "" || v == " " {

		// 			if *flagDebug {
		// 				fmt.Println(t.file, "skipping record", count, "due to missing field for column", s.columns[index], "label:", r[len(r)-1])
		// 			}

		// 			//fmt.Println(r)
		// 			skipped++
		// 			count++
		// 			skip = true
		// 		}
		// 	}
		// 	if skip {
		// 		continue
		// 	}
		// }
		if *flagZeroIncompleteRecords {
			for index, v := range r {
				if v == "" || v == " " {
					r[index] = "0"
				}
			}
		}

		// TODO: make configurable
		// fields Network CSV:
		// 0  num
		// 1  date
		// 2  time
		// 3  orig
		// 4  type
		// 5  i/f_name
		// 6  i/f_dir
		// 7  src
		// 8  dst
		// 9  proto
		// 10 appi_name
		// 11 proxy_src_ip
		// 12 Modbus_Function_Code
		// 13 Modbus_Function_Description
		// 14 Modbus_Transaction_ID
		// 15 SCADA_Tag
		// 16 Modbus_Value
		// 17 service
		// 18 s_port
		// 19 Tag

		// example:
		// num,date,time,orig,type,i/f_name,i/f_dir,src,dst,proto,appi_name,proxy_src_ip,Modbus_Function_Code,Modbus_Function_Description,Modbus_Transaction_ID,SCADA_Tag,Modbus_Value,service,s_port,Tag
		// 1,21Dec2015,22:17:56,192.168.1.48,log,eth1,outbound,192.168.1.60,192.168.1.10,tcp,CIP_read_tag_service,192.168.1.60,76,Read Tag Service,30721,HMI_LIT101,Number of Elements: 1,44818,53260,0

		var classification = "normal"

		ti, err := time.Parse("2Jan200615:04:05", r[1]+r[2])
		if err != nil {
			ti, err = time.Parse("2Jan0615:04:05", r[1]+r[2])
			if err != nil {
				ti, err = time.Parse("2-Jan-0615:04:05", r[1]+r[2])
				if err != nil {
					log.Println(info, err, "file:", t.file, "line:", count)
					sec, err := strconv.ParseInt(r[1]+r[2], 10, 64)
					if err != nil {
						fmt.Println(info, " no valid timestamp format found!", t.file)
						continue
					}
					ti = time.Unix(sec, 0)
				}
			}
		}
		//fmt.Println(r[1]+r[2], "time:", ti)

		// determine classification
		for _, a := range attacks {
			if a.during(ti) {
				if a.affectsHosts(r[7], r[8]) {
					classification = a.AttackType
					//fmt.Println("match for", a.AttackName)

					hitMapLock.Lock()
					hitMap[a.AttackName]++
					hitMapLock.Unlock()

					numMatches++

					// 1 attack match max at the moment
					break
				}
			}
		}

		// fix for additional column in dataset: Referrer_self_uid
		// this column will be dropped from the dataset
		// num,date,time,orig,type,i/f_name,i/f_dir,src,dst,proto,appi_name,proxy_src_ip,Modbus_Function_Code,Modbus_Function_Description,Modbus_Transaction_ID,SCADA_Tag,Modbus_Value,service,s_port,Referrer_self_uid,Tag
		if len(r) == 21 {
			// remove last elem: the value for tag
			// the last column then contains the Referrer_self_uid, which will be overwritten with the value for the classification
			// this is more efficient than shifting values between columns
			r = r[:20]
		}

		// TODO kills performance, refactor ...
		// apply value corrections
		// for index, v := range r {
		// 	if corr, ok := cmap[inputHeader[index]]; ok {
		// 		for _, c := range corr {
		// 			if v == c.old {
		// 				if *flagDebug {
		// 					fmt.Println("correction: changed", r[index], "to", c.new)
		// 				}
		// 				r[index] = c.new
		// 			}
		// 		}
		// 	}
		// }

		// apply value corrections
		for index, v := range r {
			if new, ok := simpleCorrect[v]; ok {
				fmt.Println(t.file, ": correction: changed", r[index], "to", new)
				r[index] = new
			}
		}

		if *flagEncode {
			// encode values
			for index, v := range r {

				// get column name
				colName := inputHeader[index]

				// skip over values for excluded columns
				if excluded(colName) {
					continue
				}

				// lookup summary for column
				if sum, ok := colSums[colName]; ok {

					// handle data type
					switch sum.Typ {
					case encoder.TypeString:

						if *flagEncodeCategoricals {

							// get index num
							i, found := sum.UniqueStrings[v]
							if !found {
								log.Println("value not found", v)
								continue
							}

							if *flagNormalizeCategoricals {
								// TODO: make normalization a second stage?
								// normalize
								if *flagZScore {
									r[index] = encoder.ZScore(i, sum)
								} else {
									r[index] = encoder.MinMax(i, sum)
								}
							} else {
								r[index] = strconv.FormatInt(int64(i), 10)
							}
						}

					case encoder.TypeNumeric:

						// parse numbers as float
						i, err := strconv.ParseFloat(v, 64)
						if err != nil {
							ii, err := strconv.Atoi(v)
							if err != nil {
								fmt.Println(ansi.Red, r, ansi.Reset)
								fmt.Println("[WARNING] failed to parse number: ", v, " file: ", t.file, " line: ", count, " column: ", colName, "setting it to zero by default!")

								// we use zero to mark places with missing values
								r[index] = "0"

								continue
							}
							i = float64(ii)
						}

						// TODO: make normalization a second stage?
						// normalize
						if *flagZScore {
							r[index] = encoder.ZScore(i, sum)
						} else {
							r[index] = encoder.MinMax(i, sum)
						}
					}
				}
			}
		}

		// remove leading num and date columns
		r = r[2:]

		// insert UNIX timestamp, normalized using minMax
		// TODO: hardcoded min max due to time constraints, calculate it during analyze run
		// ts min 1451297796
		// ts max 1451743308
		// delta: 1451743308-1451297796 = 445512
		r[0] = strconv.FormatFloat(float64(ti.Unix()-1451297796)/(445512), 'f', precision, 64)

		// replace values in 'Tag' column with classification
		r[len(r)-1] = classification

		// ensure no corrupted data is written into the output file
		if len(r) != outputHeaderLen {
			fmt.Println(info, "file:", t.file, "line:", count)
			log.Fatal("length of data line does not match header length:", len(r), "!=", len(outputHeader))
		}

		// write line
		err = outputWriter.Write(r)
		if err != nil {
			log.Fatal(err)
		}
	}

	outputWriter.Flush()
	err = outputWriter.Error()
	if err != nil {
		log.Fatal(err)
	}

	// -1 for the header
	fmt.Println(info, count-1, "records,", numMatches, "attacks written to", filepath.Base(outputFile.Name()))
	t.wg.Done()
}
