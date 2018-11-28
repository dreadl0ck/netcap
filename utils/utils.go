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

package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
)

// Pad the input up to the given number of space characters
func Pad(in interface{}, length int) string {
	return fmt.Sprintf("%-"+strconv.Itoa(length)+"s", in)
}

// DumpProto prints a protobuf message formatted
func DumpProto(pb proto.Message) {
	fmt.Println(proto.MarshalTextString(pb))
}

// ClearScreen prints ANSI escape to flush screen
func ClearScreen() {
	print("\033[H\033[2J")
}

// ClearLine clears the current line of the terminal
func ClearLine() {
	print("\033[2K\r")
}

// Progress display
func Progress(current, total int64) string {
	var b []byte
	b = strconv.AppendInt(b, int64((float64(current)/float64(total))*100), 10)
	b = append(b, byte(37)) // dec 37 == PERCENT_SIGN (%)
	return string(b)
}

func TrimFileExtension(file string) string {
	return strings.TrimSuffix(strings.TrimSuffix(file, ".gz"), ".ncap")
}

// TimeToUTC returns a time string in netcap format to a UTC string
func TimeToUTC(val string) string {
	if slice := strings.Split(val, "."); len(slice) == 2 {
		// seconds
		seconds, err := strconv.ParseInt(slice[0], 10, 64)
		if err != nil {
			return err.Error()
		}

		// microseconds
		micro, err := strconv.ParseInt(slice[1], 10, 64)
		if err != nil {
			return err.Error()
		}
		return time.Unix(seconds, micro*1000).UTC().String()
	} else {
		return "invalid timestamp: " + val
	}
}

// func decodemac(pkt []byte) uint64 {
// 	mac := uint64(0)
// 	for i := uint(0); i < 6; i++ {
// 		mac = (mac << 8) + uint64(pkt[i])
// 	}
// 	return mac
// }

// StringToTime converts a seconds.micro string to a time.Time
func StringToTime(val string) time.Time {

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
		return time.Unix(seconds, micro*1000)
	}

	return time.Time{}
}

// TimeToString converts a time.Time to seconds.micro string
func TimeToString(t time.Time) string {
	var b []byte
	b = strconv.AppendInt(b, t.Unix(), 10)
	b = append(b, byte(46)) // 46 dec == "." FULL_STOP
	b = strconv.AppendInt(b, int64(t.Nanosecond()/1000), 10)
	return string(b)
}

// func sortSlice(values []types.CSV) {
// 	sort.Slice(values, func(i, j int) bool {
// 		iTime := StringToTime(values[i].NetcapTimestamp())
// 		jTime := StringToTime(values[j].NetcapTimestamp())
// 		return iTime.date.Before(jTime.date)
// 	})
// }
