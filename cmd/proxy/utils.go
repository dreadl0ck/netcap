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

package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dreadl0ck/netcap/io"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("proxy tool usage examples:")
	fmt.Println("	$ net proxy -local 127.0.0.1:4444 -remote https://github.com")
	fmt.Println("	$ net proxy -local 127.0.0.1:4444 -remote https://github.com -maxIdle 300")
	fmt.Println("	$ net proxy -local 127.0.0.1:4444 -remote https://github.com -dump")
	fmt.Println()
}

// usage prints the use.
func printUsage() {
	printHeader()
	fs.PrintDefaults()
}

// cleanup when receiving OS signals.
func cleanup() {
	for _, p := range proxies {
		// pass numRecords > 0 so that files do not get removed.
		// TODO: add support to determine the correct number of records at this place
		p.writer.Close(1)
	}
}

// handle OS signals.
func handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// start signal handler and cleanup routine
	go func() {
		sig := <-sigs

		fmt.Println("\nreceived signal:", sig)

		fmt.Println("exiting")

		cleanup()
		os.Exit(0)
	}()
}

// TrimPortIPv4 trims the port number from an IPv4 address string.
//func TrimPortIPv4(addr string) string {
//	slice := strings.Split(addr, ":")
//	if len(slice) == 2 {
//		return slice[0]
//	}
//	return addr
//}

// dumpHTTPResponse dumps an http.Response for debugging purposes.
func dumpHTTPResponse(resp *http.Response, proxyName string, rawbody []byte) {
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	fmt.Println(proxyName + " received an HTTP Response:")
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")

	var deflated []byte

	if resp.Header.Get("Content-Encoding") == "gzip" {
		var gzipBuf bytes.Buffer

		gzipBuf.Write(rawbody)

		gr, err := gzip.NewReader(&gzipBuf)
		if err != nil {
			log.Fatal("failed to create gzip reader for response: ", err)
		}

		deflated, err = ioutil.ReadAll(gr)
		if err != nil {
			log.Fatal("failed to decompress gzipped response: ", err)
		}
	}

	var (
		contentType = resp.Header.Get("Content-Type")
		isHTML      = strings.Contains(contentType, "text/html")
	)
	if len(deflated) != 0 || isHTML {
		// dump header only
		data, err := httputil.DumpResponse(resp, false)
		if err != nil {
			log.Println("failed to read response header")
		}
		fmt.Println(string(data))

		// dump deflated content if there is any
		// and if its not HTML
		if len(deflated) != 0 && !isHTML {
			fmt.Println(string(deflated))
		}
	} else {
		if !strings.Contains(contentType, "multipart") {
			// dump full response
			data, err := httputil.DumpResponse(resp, true)
			if err != nil {
				log.Println("failed to read response header")
			}
			fmt.Println(string(data))
		} else {
			fmt.Println("multipart form data: ", len(rawbody))
		}
	}

	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")
}

// dumpHTTPRequest dumps an http.Request for debugging purposes.
func dumpHTTPRequest(req *http.Request, proxyName string) {
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	fmt.Println(proxyName+" received an HTTP Request: ", req.URL)
	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")

	data, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println("failed to read req body for debug message")
	} else {
		fmt.Println(string(data))
	}

	fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")
}

// Get Remote Address, handles load balancers
// see: https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html

// ipRange - a structure that holds the start and end of a range of ip addresses.
type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given.
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}

	return false
}

var privateRanges = []ipRange{
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

// isPrivateSubnet - check to see if this ip is in a private subnet.
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}

	return false
}

// getIPAddress will retrieve the ip address of a http.Request.
func getIPAdress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}

			return ip
		}
	}

	return ""
}
