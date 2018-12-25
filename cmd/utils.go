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

package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/mgutz/ansi"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var logo = `                       / |
 _______    ______   _10 |_     _______   ______    ______
/     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                  00 |
Network Protocol Analysis Framework               00 |
created by Philipp Mieden, 2018                   00/
` + netcap.Version

func init() {
	Log.Formatter = &prefixed.TextFormatter{}
}

func printLogo() {
	utils.ClearScreen()
	fmt.Println(logo)
}

// CheckFields checks if the separator occurs inside fields of audit records
// to prevent this breaking the generated CSV file
// TODO refactor to use netcap lib to read file instead of calling it as command
func CheckFields() {

	r, err := netcap.Open(*flagInput)
	if err != nil {
		panic(err)
	}
	h := r.ReadHeader()
	record := netcap.InitRecord(h.Type)
	var numExpectedFields int
	if p, ok := record.(types.CSV); ok {
		numExpectedFields = len(p.CSVHeader())
	} else {
		log.Fatal("netcap type does not implement the types.CSV interface!")
	}
	r.Close()

	out, err := exec.Command("netcap", "-r", *flagInput).Output()
	if err != nil {
		panic(err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		count := strings.Count(line, *flagSeparator)
		if count != numExpectedFields-1 {
			fmt.Println(strings.Replace(line, *flagSeparator, ansi.Red+*flagSeparator+ansi.Reset, -1), ansi.Red, count, ansi.Reset)
		}
	}
}
