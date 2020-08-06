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
	tiStr = TimeToString(ti)
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

func TestChopTransportIdent(t *testing.T) {
	res := ChopTransportIdent("192.168.1.47->165.227.109.154-53032->80")
	if res != "53032->80" {
		t.Fatal("got", res, "expected: 53032->80")
	}
}

func TestReverseIdent(t *testing.T) {
	res := ReverseIdent("192.168.1.47->165.227.109.154-53032->80")
	if res != "165.227.109.154->192.168.1.47-80->53032" {
		t.Fatal("got", res, "expected: 165.227.109.154->192.168.1.47-80->53032")
	}
}

func TestParseIdent(t *testing.T) {
	srcIP, srcPort, dstIP, dstPort := ParseIdent("192.168.1.47->165.227.109.154-53032->80")
	if srcIP != "192.168.1.47" {
		t.Fatal("got srcIP", srcIP, "expected: 192.168.1.47")
	}
	if srcPort != "53032" {
		t.Fatal("got srcPort", srcPort, "expected: 53032")
	}
	if dstIP != "165.227.109.154" {
		t.Fatal("got dstIP", dstIP, "expected: 165.227.109.154")
	}
	if dstPort != "80" {
		t.Fatal("got dstPort", dstPort, "expected: 80")
	}
}

func TestTimeToString(t *testing.T) {
	if TimeToString(ti) != TimeToStringOld(ti) {
		t.Fatal("not the same: TimeToString(ti) != TimeToStringOld(ti)", TimeToString(ti), " != ", TimeToStringOld(ti))
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
		TimeToString(ti)
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
	tiString := TimeToString(ti)

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
