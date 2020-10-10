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

package utils

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	tins  = time.Now()
	ti    = time.Unix(tins.Unix(), int64(tins.Nanosecond()/1000*1000))
	tiStr = timeToString(ti)
)

const dotRune = 46

func isDot(r rune) bool {
	return r == dotRune
}

// TimeToStringOld is the old implementation for timeToString
func TimeToStringOld(t time.Time) string {
	micro := fmt.Sprintf("%05d", t.Nanosecond()/1000)
	return strconv.FormatInt(t.Unix(), 10) + "." + micro
}

// StringToTimeFieldsFunc converts a timestring to a time.Time
// using strings.FieldsFunc
// this appears to be slower than using strings.Split
func StringToTimeFieldsFunc(val string) time.Time {
	if slice := strings.FieldsFunc(val, isDot); len(slice) == 2 {
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

func TestTimeToString(t *testing.T) {
	if timeToString(ti) != TimeToStringOld(ti) {
		t.Fatal("not the same: TimeToString(ti) != TimeToStringOld(ti)", timeToString(ti), " != ", TimeToStringOld(ti))
	}
}

func BenchmarkTimeToStringOld(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		TimeToStringOld(ti)
	}
}

func BenchmarkTimeToString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		timeToString(ti)
	}
}

func TestStringToTime(t *testing.T) {
	tim := StringToTime(tiStr)

	if !tim.Equal(ti) {
		t.Fatal("not the same", tim)
	}
}

func BenchmarkStringToTime(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		StringToTime(tiStr)
	}
}

func BenchmarkStringToTimeFieldsFunc(b *testing.B) {
	tiString := timeToString(ti)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		StringToTimeFieldsFunc(tiString)
	}
}

func ProgressOld(current, total int64) string {
	return strconv.Itoa(int((float64(current)/float64(total))*100)) + "%"
}

func BenchmarkProgressOld(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProgressOld(int64(n), int64(b.N))
	}
}

func BenchmarkProgress(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Progress(int64(n), int64(b.N))
	}
}
