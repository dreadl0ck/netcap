/*
 * NETCAP - Network Capture Toolkit
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
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

// print as UTC
func ts2utc(val string) {
	if slice := strings.Split(val, "."); len(slice) == 2 {
		// seconds
		seconds, err := strconv.ParseInt(slice[0], 10, 64)
		if err != nil {
			panic(err)
		}

		// microseconds
		micro, err := strconv.ParseInt(slice[1], 10, 64)
		if err != nil {
			panic(err)
		}
		fmt.Println(time.Unix(seconds, micro*1000).UTC())
	} else {
		fmt.Println("invalid timestamp:" + val)
	}
}

func printLogo() {
	utils.ClearScreen()
	fmt.Println(logo)
}

func timestampToFloat(t time.Time) float64 {
	return float64(t.Unix())
}

func dumpMap(m map[string]int64, padding int) string {
	var res string
	for k, v := range m {
		res += pad(k, padding) + ": " + fmt.Sprint(v) + "\n"
	}
	return res
}

// pad the input string up to the given number of space characters
func pad(in string, length int) string {
	if len(in) < length {
		return fmt.Sprintf("%-"+strconv.Itoa(length)+"s", in)
	}
	return in
}

func macToInt(mac string) int {
	//mac := "00-15-CF-80-F8-13"
	// mac = strings.Replace(mac, "-", "", -1) // the last argument could be 5 instead
	// return strconv.Btoui64(mac, 16)
	return 0
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func share(current, total int64) string {
	percent := (float64(current) / float64(total)) * 100
	return strconv.FormatFloat(percent, 'f', 5, 64) + "%"
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
