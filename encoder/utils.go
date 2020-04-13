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

package encoder

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
)

// MarkdownOverview dumps a Markdown summary of all available encoders and their fields
func MarkdownOverview() {
	fmt.Println("# NETCAP Overview " + netcap.Version)
	fmt.Println("> Documentation: [docs.netcap.io](https://docs.netcap.io)")
	fmt.Println("## LayerEncoders")

	fmt.Println("|Name|NumFields|Fields|")
	fmt.Println("|----|---------|------|")
	for _, e := range layerEncoderSlice {
		if csv, ok := netcap.InitRecord(e.Type).(types.AuditRecord); ok {
			fmt.Println("|"+pad(e.Layer.String(), 30)+"|", len(csv.CSVHeader()), "|"+strings.Join(csv.CSVHeader(), ", ")+"|")
		}
	}

	fmt.Println("## CustomEncoders")

	fmt.Println("|Name|NumFields|Fields|")
	fmt.Println("|----|---------|------|")
	for _, e := range customEncoderSlice {
		if csv, ok := netcap.InitRecord(e.Type).(types.AuditRecord); ok {
			fmt.Println("|"+pad(e.Name, 30)+"|", len(csv.CSVHeader()), "|"+strings.Join(csv.CSVHeader(), ", ")+"|")
		}
	}
}

func recovery() {
	if r := recover(); r != nil {
		errorsMapMutex.Lock()
		errorsMap[fmt.Sprint(r)]++
		errorsMapMutex.Unlock()
	}
}

func printProgress(current, total int64) {
	if current%5 == 0 {
		clearLine()
		print("flushing http traffic... (" + progress(current, total) + ")")
	}
}

func progress(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	return strconv.Itoa(int(percent)) + "%"
}

func clearLine() {
	print("\033[2K\r")
}

func calcMd5(s string) string {

	var out []byte
	for _, b := range md5.Sum([]byte(s)) {
		out = append(out, b)
	}

	return hex.EncodeToString(out)
}

func ShowEncoders() {
	fmt.Println("custom:", len(customEncoderSlice))
	for _, e := range customEncoderSlice {
		fmt.Println("+", e.Name)
	}
	fmt.Println("layer:", len(layerEncoderSlice))
	for _, e := range layerEncoderSlice {
		fmt.Println("+", e.Layer.String())
	}
}

// Entropy returns the shannon entropy value
// https://rosettacode.org/wiki/Entropy#Go
func Entropy(data []byte) (entropy float64) {
	if len(data) == 0 {
		return 0
	}
	for i := 0; i < 256; i++ {
		px := float64(bytes.Count(data, []byte{byte(i)})) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}
	return entropy
}

// pad the input up to the given number of space characters
func pad(in interface{}, length int) string {
	return fmt.Sprintf("%-"+strconv.Itoa(length)+"s", in)
}

func logReassemblyError(t string, s string, a ...interface{}) {
	errorsMapMutex.Lock()
	numErrors++
	nb := errorsMap[t]
	errorsMap[t] = nb + 1
	errorsMapMutex.Unlock()

	if c.Debug {
		reassemblyLog.Printf("ERROR: "+s, a...)
	}
}

func logReassemblyInfo(s string, a ...interface{}) {
	if c.Debug {
		reassemblyLog.Printf("INFO: "+s, a...)
	}
}

func logReassemblyDebug(s string, a ...interface{}) {
	if c.Debug {
		reassemblyLog.Printf("DEBUG: "+s, a...)
	}
}

// Cleanup closes the logfile handles
func Cleanup() {
	if reassemblyLogFileHandle != nil {
		reassemblyLogFileHandle.Close()
	}
	if debugLogFileHandle != nil {
		debugLogFileHandle.Close()
	}
}
