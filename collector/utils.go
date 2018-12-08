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

package collector

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
)

// print live statistics
func (c *Collector) printProgressLive() {

	// must be locked, otherwise a race occurs when sending a SIGINT and triggering wg.Wait() in another goroutine...
	c.statMutex.Lock()
	c.wg.Add(1)
	c.statMutex.Unlock()

	c.current++
	if c.current%1000 == 0 {
		clearLine()
		fmt.Print("running since ", time.Since(c.start), ", captured ", c.current, " packets...")
	}
}

func DumpProto(pb proto.Message) {
	println(proto.MarshalTextString(pb))
}

// ClearScreen prints ANSI escape to flush screen
func clearScreen() {
	print("\033[H\033[2J")
}

func clearLine() {
	print("\033[2K\r")
}

func stringIsSet(flagValue *string) bool {
	return *flagValue != ""
}

func boolIsSet(flagValue *bool) bool {
	return *flagValue == true
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

// creates a sha256 hash with the timestamp of the packet and all packet data
// and returns a hex string
// currently not in use
func (c *Collector) calcPacketID(p gopacket.Packet) string {

	var out []byte
	for _, b := range md5.Sum(append([]byte(p.Metadata().Timestamp.String()), p.Data()...)) {
		out = append(out, b)
	}

	return hex.EncodeToString(out)
}
