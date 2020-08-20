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
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/blevesearch/bleve"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/evilsocket/islazy/tui"
)

// noPluralsMap contains words for which to make an exception when pluralizing nouns.
var noPluralsMap = map[string]struct{}{
	"Software": {},
	"Ethernet": {},
}

// OpenBleve is a simple wrapper for the bleve open call
// it's used to log any open operations.
func OpenBleve(path string) (bleve.Index, error) {
	if DebugLogFileHandle != nil {
		DebugLog.Println("opening bleve db at path:", path)
	}

	return bleve.Open(path)
}

// CloseBleve is a simple wrapper for the bleve close call
// it's used to log any close operations.
func CloseBleve(index io.Closer) {
	if index == nil {
		return
	}

	if DebugLogFileHandle != nil {
		DebugLog.Println("closing bleve db:", index)
	}

	err := index.Close()
	if err != nil {
		fmt.Println(err)
	}
}

// Pluralize returns the plural for a given noun.
func Pluralize(name string) string {
	if strings.HasSuffix(name, "e") || strings.HasSuffix(name, "w") {
		if _, ok := noPluralsMap[name]; !ok {
			name += "s"
		}
	}

	if strings.HasSuffix(name, "y") {
		name = name[:len(name)-1] + "ies"
	}

	if strings.HasSuffix(name, "t") {
		if _, ok := noPluralsMap[name]; !ok {
			name += "s"
		}
	}

	return name
}

// IsASCII checks if input consists of ascii characters.
func IsASCII(d []byte) bool {
	if len(d) == 0 {
		return false
	}

	for i := 0; i < len(d); i++ {
		if d[i] > unicode.MaxASCII {
			return false
		}
	}

	return true
}

// ListAllNetworkInterfaces dumps a list of all visible network interfaces to stdout.
func ListAllNetworkInterfaces() {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("failed to get network interfaces: ", err)
	}

	var (
		rows  = make([][]string, len(interfaces))
		index int
	)

	for _, nic := range interfaces {
		rows[index] = []string{strconv.Itoa(nic.Index), nic.Name, nic.Flags.String(), nic.HardwareAddr.String(), strconv.Itoa(nic.MTU)}
		index++
	}

	tui.Table(os.Stdout, []string{"Index", "Name", "Flags", "HardwareAddr", "MTU"}, rows)
}

// GetBaseLayer resolves a baselayer string to the gopacket.LayerType.
func GetBaseLayer(value string) (t gopacket.LayerType) {
	switch value {
	case "ethernet":
		t = layers.LayerTypeEthernet
	case "ipv4":
		t = layers.LayerTypeIPv4
	case "ipv6":
		t = layers.LayerTypeIPv6
	case "usb":
		t = layers.LayerTypeUSB
	default:
		log.Fatal("invalid baseLayer:", value)
	}

	return
}

// GetDecodeOptions resolves a decode option string to the gopacket.DecodeOptions type.
func GetDecodeOptions(value string) (o gopacket.DecodeOptions) {
	switch value {
	case "lazy":
		o = gopacket.Lazy
	case "default":
		o = gopacket.Default
	case "nocopy":
		o = gopacket.NoCopy
	case "datagrams":
		o = gopacket.DecodeStreamsAsDatagrams
	default:
		log.Fatal("invalid decode options:", value)
	}

	return
}

// Pad the input up to the given number of space characters..
func Pad(in interface{}, length int) string {
	return fmt.Sprintf("%-"+strconv.Itoa(length)+"s", in)
}

// DumpProto prints a protobuf message formatted.
// func DumpProto(pb proto.Message) {
// 	fmt.Println(proto.MarshalTextString(pb))
// }

// ClearScreen prints ANSI escape to flush screen.
func ClearScreen() {
	print("\033[H\033[2J")
}

// ClearLine clears the current line of the terminal.
func ClearLine() {
	print("\033[2K\r")
}

// Progress returns the value in percent as a string suffixed with a %.
func Progress(current, total int64) string {
	if total == 0 {
		return strconv.FormatInt(current, 10)
	}

	var b []byte

	b = strconv.AppendInt(b, int64((float64(current)/float64(total))*100), 10)
	b = append(b, byte(37)) // dec 37 == PERCENT_SIGN (%)

	return string(b)
}

// GetPercentage returns the value in percent as a string.
// func GetPercentage(current, total int64) string {
// 	if total == 0 {
// 		return strconv.FormatInt(current, 10)
// 	}
// 	var b []byte
// 	b = strconv.AppendInt(b, int64((float64(current)/float64(total))*100), 10)
// 	return string(b)
// }

// TrimFileExtension returns the netcap file name without file extension.
func TrimFileExtension(file string) string {
	return strings.TrimSuffix(strings.TrimSuffix(file, ".gz"), ".ncap")
}

// TimeToUTC returns a time string in netcap format to a UTC string.
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
	}

	return val
}

// TimeToUnixMilli returns a time string in netcap format to a Unix millisecond time.
func TimeToUnixMilli(val string) string {

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

		return strconv.FormatInt(time.Unix(seconds, micro*1000).UTC().UnixNano()/int64(time.Millisecond), 10)
	}

	return val
}

// func decodemac(pkt []byte) uint64 {
// 	mac := uint64(0)
// 	for i := uint(0); i < 6; i++ {
// 		mac = (mac << 8) + uint64(pkt[i])
// 	}
// 	return mac
// }

// StringToTime converts a seconds.micro string to a time.Time.
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

// TimeToString converts a time.Time to seconds.micro string.
func TimeToString(t time.Time) string {
	var b []byte
	b = strconv.AppendInt(b, t.Unix(), 10)
	b = append(b, byte(46)) // 46 dec == "." FULL_STOP
	b = strconv.AppendInt(b, int64(t.Nanosecond()/1000), 10)

	return string(b)
}

// func sortSlice(values []types.AuditRecord) {
// 	sort.Slice(values, func(i, j int) bool {
// 		iTime := StringToTime(values[i].Time())
// 		jTime := StringToTime(values[j].Time())
// 		return iTime.date.Before(jTime.date)
// 	})
// }
