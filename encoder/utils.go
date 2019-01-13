/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
)

func Overview() {
	fmt.Println("------------ LayerEncoders ------------")
	for _, e := range layerEncoderSlice {
		if csv, ok := netcap.InitRecord(e.Type).(types.CSV); ok {
			fmt.Println(pad(e.Layer.String(), 30), len(csv.CSVHeader()), strings.Join(csv.CSVHeader(), ","))
		}
	}

	fmt.Println("------------ CustomEncoders ------------")
	for _, e := range customEncoderSlice {
		if csv, ok := netcap.InitRecord(e.Type).(types.CSV); ok {
			fmt.Println(pad(e.Name, 30), len(csv.CSVHeader()), strings.Join(csv.CSVHeader(), ","))
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
	fmt.Println("custom:")
	for _, e := range customEncoderSlice {
		fmt.Println("+", e.Name)
	}
	fmt.Println("layer:")
	for _, e := range layerEncoderSlice {
		fmt.Println("+", e.Layer.String())
	}
}

func CloseGzipWriters(writers ...*gzip.Writer) {
	for _, w := range writers {
		err := w.Flush()
		if err != nil {
			panic(err)
		}
		err = w.Close()
		if err != nil {
			panic(err)
		}
	}
}

func RemoveEmptyFile(name string) (size int64) {

	if strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".csv.gz") {
		f, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		var r *bufio.Reader
		if strings.HasSuffix(name, ".csv.gz") {
			gr, err := gzip.NewReader(f)
			if err != nil {
				panic(err)
			}
			r = bufio.NewReader(gr)
		} else {
			r = bufio.NewReader(f)
		}

		count := 0
		for {
			_, _, err := r.ReadLine()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}
			count++
			if count > 1 {
				break
			}
		}

		if count < 2 {
			// remove file
			err = os.Remove(name)
			if err != nil {
				fmt.Println("failed to remove file", err)
			}

			// return file size of zero
			return 0
		}

		// dont remove file
		// return final file size
		s, err := os.Stat(name)
		if err != nil {
			fmt.Println("failed to stat file:", name, err)
			return
		}
		return s.Size()
	}

	r, err := netcap.Open(name)
	if err != nil {
		fmt.Println("unable to open file:", name, "error", err)
		return 0
	}
	defer r.Close()

	var (
		header = r.ReadHeader()
		record = netcap.InitRecord(header.Type)
	)

	err = r.Next(record)
	if err != nil {
		// remove file
		err = os.Remove(name)
		if err != nil {
			fmt.Println("failed to remove file", err)

			// return file size of zero
			return 0
		}
		return
	}

	// dont remove file
	// return final file size
	s, err := os.Stat(name)
	if err != nil {
		fmt.Println("failed to stat file:", name, err)
		return
	}
	return s.Size()
}

func CloseFile(outDir string, file *os.File, typ string) (name string, size int64) {

	i, err := file.Stat()
	if err != nil {
		fmt.Println("[ERROR] closing file:", err, "type", typ)
		return "", 0
	}

	var (
		errSync  = file.Sync()
		errClose = file.Close()
	)
	if errSync != nil || errClose != nil {
		fmt.Println("error while closing", i.Name(), "errSync", errSync, "errClose", errClose)
	}

	return i.Name(), RemoveEmptyFile(filepath.Join(outDir, i.Name()))
}

func CreateFile(name, ext string) *os.File {
	f, err := os.Create(name + ext)
	if err != nil {
		panic(err)
	}
	return f
}

type flushableWriter interface {
	Flush() error
}

func FlushWriters(writers ...flushableWriter) {
	for _, w := range writers {
		err := w.Flush()
		if err != nil {
			panic(err)
		}
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
