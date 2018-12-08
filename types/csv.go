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

package types

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	proto "github.com/golang/protobuf/proto"
	"github.com/mgutz/ansi"
)

var (
	selection []int
	UTC       bool
)

type CSV interface {

	// returns CSV values
	CSVRecord() []string

	// returns CSV header fields
	CSVHeader() []string

	// used for labeling
	NetcapTimestamp() string
}

func selectFields(all []string, selection string) (s []int) {

	var (
		fields = strings.Split(selection, ",")
		ok     bool
	)

	s = make([]int, len(fields))
	for i, val := range fields {
		for index, name := range all {
			if name == val {
				s[i] = index
				ok = true
				break
			}
		}
		if !ok {
			fmt.Println("invalid field: ", ansi.Red+val+ansi.Reset)
			fmt.Println("available fields: ", ansi.Yellow+strings.Join(all, ",")+ansi.Reset)
			os.Exit(1)
		}
		ok = false
	}
	return s
}

func Select(msg proto.Message, vals string) {
	if vals != "" && vals != " " {
		if p, ok := msg.(CSV); ok {
			selection = selectFields(p.CSVHeader(), vals)
		} else {
			log.Fatal("netcap type does not implement the netcap.ToCSV interface!")
		}
	}
}

func filter(in []string) []string {
	if len(selection) == 0 {
		return in
	}
	r := make([]string, len(selection))
	for i, v := range selection {
		r[i] = in[v]
	}
	return r
}

// pad the input up to the given number of space characters
func pad(v interface{}, length int) string {
	return fmt.Sprintf("%-"+strconv.Itoa(length)+"s", fmt.Sprint(v))
}
