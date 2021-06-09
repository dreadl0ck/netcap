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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/evilsocket/islazy/tui"
)

/*
 * Utils
 */

func makeIntSlice(max int) []float64 {
	var arr = make([]float64, max)
	for i := 0; i < max; i++ {
		arr[i] = float64(i)
	}
	return arr
}

// TODO: check if sorting is faster
// func MinIntSlice(v []int) int {
// 	sort.Ints(v)
// 	return v[0]
// }

// func MaxIntSlice(v []int) int {
// 	sort.Ints(v)
// 	return v[len(v)-1]
// }

var excludedCols = []string{"num", "date", "time", "Referrer_self_uid"}

func excluded(col string) bool {
	for _, ex := range excludedCols {
		if ex == col {
			return true
		}
	}
	return false
}

func contains(arr []string, val string) bool {
	for _, v := range arr {
		if strings.Contains(val, v) {
			return true
		}
	}
	return false
}

// ClearLine clears the current line of the terminal
func clearLine() {
	print("\033[2K\r")
}

func runLabeling(files []string, wg *sync.WaitGroup, totalFiles int) {
	for current, file := range files[*flagOffset:*flagMaxFiles] {
		wg.Add(1)
		handleTask(task{
			typ:        typeLabel,
			file:       file,
			current:    current,
			totalFiles: totalFiles,
			wg:         wg,
		})
	}

	fmt.Println("started all labeling jobs, waiting...")
	wg.Wait()

	printLabelInfo()
}

func printAnalysisInfo() {

	fmt.Println("------- printAnalysisInfo")

	fmt.Println("analyzing data...")
	colSums = merge(results)
	if *flagDebug {
		if colSums != nil {
			for _, sum := range colSums {
				if sum.Col != "Modbus_Value" {
					spew.Dump(sum)
				}
			}
		}
	}

	fmt.Println("saving column summaries...")

	data, err := json.Marshal(colSums)
	if err != nil {
		log.Fatal("failed to json marshal", err)
	}

	f, err := os.Create("colSums-" + time.Now().Format("2Jan2006-150405") + ".json")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("saved column summaries to", f.Name())
}

func printLabelInfo() {

	fmt.Println("------- printLabelInfo")

	// sort and print mapping stats
	var atks attackResults
	for n, hits := range hitMap {
		atks = append(atks, attackResult{
			name: n,
			hits: hits,
		})
	}

	sort.Sort(atks)

	var rows [][]string
	for _, a := range atks {
		rows = append(rows, []string{strconv.Itoa(a.hits), a.name})
	}

	tui.Table(os.Stdout, []string{"Hits", "AttackName"}, rows)

	// print names of attacks that could not be mapped
	var notMatched []string
	for _, a := range attacks {
		if _, ok := hitMap[a.AttackName]; !ok {
			notMatched = append(notMatched, a.AttackName)
		}
	}
	if len(notMatched) > 0 {
		fmt.Println("could not map the following attacks:")
	}
	for _, name := range notMatched {
		fmt.Println("-", name)
	}

	for file, sum := range results {
		fmt.Println(file, sum)
	}
}
