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
	"io"
	"log"
	"os"
	"strconv"

	"github.com/mgutz/ansi"
)

func (t task) analyze() *fileSummary {

	info := "[" + strconv.Itoa(t.current+1) + "/" + strconv.Itoa(t.totalFiles) + "]"
	fmt.Println(info, "processing", t.file)

	inputFile, err := os.Open(t.file)
	if err != nil {
		log.Fatal(err)
	}
	defer inputFile.Close()

	s := &fileSummary{
		file:          t.file,
		strings:       make(map[string]map[string]int),
		uniqueAttacks: make(map[string]struct{}),
	}

	var (
		inputReader = csv.NewReader(inputFile)
		//outputWriter      = csv.NewWriter(outputFile)
		//numMatches int
		count   int
		skipped int
		attacks int
	)
	if *flagReuseLineBuffer {
		inputReader.ReuseRecord = true
	}

	var (
		r          []string
		lastRecord int
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
			s.columns = make([]string, len(r))

			// copy header, to allow reusing the record slice
			for i, elem := range r {
				s.columns[i] = elem
			}

			lastRecord = len(r) - 1
			continue
		}

		if *flagCountAttacks {
			if r[lastRecord] != "normal" {
				attacks++
				s.uniqueAttacks[r[lastRecord]] = struct{}{}
				continue
			}
		}

		if *flagSkipIncompleteRecords {
			skip := false
			for index, v := range r {
				if v == "" || v == " " {

					if *flagDebug {
						fmt.Println(t.file, "skipping record", count, "due to missing field for column", s.columns[index], "label:", r[len(r)-1])
					}

					skipped++
					count++
					skip = true
				}
			}
			if skip {
				continue
			}
		}
		if *flagZeroIncompleteRecords {
			for index, v := range r {
				if v == "" || v == " " {
					r[index] = "0"
				}
			}
		}

		// count values for each column
		for i, col := range s.columns {

			if excluded(col) {
				continue
			}

			// ensure the corresponding map is initialized
			if _, ok := s.strings[col]; !ok {
				s.strings[col] = make(map[string]int)
			}
			s.strings[col][r[i]]++
		}
	}

	t.wg.Done()
	s.lineCount = count - 1 // -1 for the CSV header
	s.skipped = skipped
	s.attacks = attacks

	return s
}
