/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
	ti    = time.Now()
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
