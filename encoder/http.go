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

package encoder

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/evilsocket/islazy/tui"
	"github.com/golang/protobuf/proto"
)

var httpEncoder = CreateCustomEncoder(types.Type_NC_HTTP, "HTTP", func(d *CustomEncoder) error {

	// postinit:
	// set debug level
	// and ensure HTTP collection is enabled

	if *debug {
		outputLevel = 2
	} else if *verbose {
		outputLevel = 1
	} else if *quiet {
		outputLevel = -1
	}

	// TODO:
	//assembler.AssemblerOptions.MaxBufferedPagesPerConnection = 12
	//assembler.AssemblerOptions.MaxBufferedPagesTotal = 128

	return nil
}, func(packet gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {

	// de-init: finishes processing
	// and prints statistics

	if !Quiet {
		errorsMapMutex.Lock()
		fmt.Fprintf(os.Stderr, "HTTPEncoder: Processed %v packets (%v bytes) in %v (errors: %v, type:%v)\n", count, dataBytes, time.Since(start), numErrors, len(errorsMap))
		errorsMapMutex.Unlock()

		// print configuration
		// print configuration as table
		tui.Table(os.Stdout, []string{"TCP Reassembly Setting", "Value"}, [][]string{
			{"FlushEvery", strconv.Itoa(*flushevery)},
			{"CloseTimeout", closeTimeout.String()},
			{"Timeout", timeout.String()},
			{"AllowMissingInit", strconv.FormatBool(*allowmissinginit)},
			{"IgnoreFsmErr", strconv.FormatBool(*ignorefsmerr)},
			{"NoOptCheck", strconv.FormatBool(*nooptcheck)},
			{"Checksum", strconv.FormatBool(*checksum)},
			{"NoDefrag", strconv.FormatBool(*nodefrag)},
			{"WriteIncomplete", strconv.FormatBool(*writeincomplete)},
		})
		fmt.Println() // add a newline
	}

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			return err
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("failed to write heap profile:", err)
		}
		if err := f.Close(); err != nil {
			log.Fatal("failed to close heap profile file:", err)
		}
	}

	// TODO: dump number of pending streams
	// TODO: this + reassembly stats printing should be done independently of HTTP decoder
	fmt.Println("waiting for last streams to finish or time-out, timeout:", timeout)
	//StreamPool.Dump()
	streamFactory.WaitGoRoutines()

	if !Quiet {
		printProgress(1, 1)
		fmt.Println("")

		rows := [][]string{}
		if !*nodefrag {
			rows = append(rows, []string{"IPdefrag", strconv.Itoa(reassemblyStats.ipdefrag)})
		}
		rows = append(rows, []string{"missed bytes", strconv.Itoa(reassemblyStats.missedBytes)})
		rows = append(rows, []string{"total packets", strconv.Itoa(reassemblyStats.pkt)})
		rows = append(rows, []string{"rejected FSM", strconv.Itoa(reassemblyStats.rejectFsm)})
		rows = append(rows, []string{"rejected Options", strconv.Itoa(reassemblyStats.rejectOpt)})
		rows = append(rows, []string{"reassembled bytes", strconv.Itoa(reassemblyStats.sz)})
		rows = append(rows, []string{"total TCP bytes", strconv.Itoa(reassemblyStats.totalsz)})
		rows = append(rows, []string{"conn rejected FSM", strconv.Itoa(reassemblyStats.rejectConnFsm)})
		rows = append(rows, []string{"reassembled chunks", strconv.Itoa(reassemblyStats.reassembled)})
		rows = append(rows, []string{"out-of-order packets", strconv.Itoa(reassemblyStats.outOfOrderPackets)})
		rows = append(rows, []string{"out-of-order bytes", strconv.Itoa(reassemblyStats.outOfOrderBytes)})
		rows = append(rows, []string{"biggest-chunk packets", strconv.Itoa(reassemblyStats.biggestChunkPackets)})
		rows = append(rows, []string{"biggest-chunk bytes", strconv.Itoa(reassemblyStats.biggestChunkBytes)})
		rows = append(rows, []string{"overlap packets", strconv.Itoa(reassemblyStats.overlapPackets)})
		rows = append(rows, []string{"overlap bytes", strconv.Itoa(reassemblyStats.overlapBytes)})

		tui.Table(os.Stdout, []string{"TCP Stat", "Value"}, rows)

		if numErrors != 0 {
			rows = [][]string{}
			for e := range errorsMap {
				rows = append(rows, []string{e, strconv.FormatUint(uint64(errorsMap[e]), 10)})
			}
			tui.Table(os.Stdout, []string{"Error Subject", "Count"}, rows)
		}

		fmt.Println("\nencountered", numErrors, "errors during processing.", "HTTP requests", requests, " responses", responses)
		fmt.Println("httpEncoder.numRequests", e.numRequests)
		fmt.Println("httpEncoder.numResponses", e.numResponses)
		fmt.Println("httpEncoder.numUnmatchedResp", e.numUnmatchedResp)
		fmt.Println("httpEncoder.numNilRequests", e.numNilRequests)
		fmt.Println("httpEncoder.numFoundRequests", e.numFoundRequests)
		fmt.Println("httpEncoder.numUnansweredRequests", e.numUnansweredRequests)
	}

	return nil
})

/*
 *	Utils
 */

// set HTTP request on types.HTTP
func setRequest(h *types.HTTP, req *http.Request) {

	// set basic info
	h.Timestamp = req.Header.Get("netcap-ts")
	h.Proto = req.Proto
	h.Method = req.Method
	h.Host = req.Host
	h.ReqContentLength = int32(req.ContentLength)
	h.ReqContentEncoding = req.Header.Get("Content-Encoding")
	h.ContentType = req.Header.Get("Content-Type")
	h.RequestHeader = readHeader(req.Header)

	body, err := ioutil.ReadAll(req.Body)
	if err == nil {
		h.ContentTypeDetected = http.DetectContentType(body)

		// decompress if required
		if h.ReqContentEncoding == "gzip" {
			r, err := gzip.NewReader(bytes.NewReader(body))
			if err == nil {
				body, err = ioutil.ReadAll(r)
				if err == nil {
					h.ContentTypeDetected = http.DetectContentType(body)
				}
			}
		}
	}

	// manually replace commas, to avoid breaking them the CSV
	// use the -check flag to validate the generated CSV output and find errors quickly
	h.UserAgent = strings.Replace(req.UserAgent(), ",", "(comma)", -1)
	h.Referer = strings.Replace(req.Referer(), ",", "(comma)", -1)
	h.URL = strings.Replace(req.URL.String(), ",", "(comma)", -1)

	// retrieve ip addresses set on the request while processing
	h.SrcIP = req.Header.Get("netcap-clientip")
	h.DstIP = req.Header.Get("netcap-serverip")

	h.ReqCookies = readCookies(req.Cookies())
	h.Parameters = readParameters(req.Form)
}

func readCookies(cookies []*http.Cookie) []*types.HTTPCookie {
	var cks = make([]*types.HTTPCookie, 0)
	for _, c := range cookies {
		if c != nil {
			cks = append(cks, &types.HTTPCookie{
				Name:     c.Name,
				Value:    c.Value,
				Path:     c.Path,
				Domain:   c.Domain,
				Expires:  uint64(c.Expires.Unix()),
				MaxAge:   int32(c.MaxAge),
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
				SameSite: int32(c.SameSite),
			})
		}
	}
	return cks
}

func newHTTPFromResponse(res *http.Response) *types.HTTP {

	var (
		detected string
		contentLength = int32(res.ContentLength)
	)

	// read body data
	body, err := ioutil.ReadAll(res.Body)
	if err == nil {

		if contentLength == -1 {
			// determine length manually
			contentLength = int32(len(body))
		}

		// decompress payload if required
		if res.Header.Get("Content-Encoding") == "gzip" {
			r, err := gzip.NewReader(bytes.NewReader(body))
			if err == nil {
				body, err = ioutil.ReadAll(r)
				if err == nil {
					detected = http.DetectContentType(body)
				}
			}
		} else {
			detected = http.DetectContentType(body)
		}
	}

	return &types.HTTP{
		ResContentLength:       contentLength,
		ResContentType:         res.Header.Get("Content-Type"),
		StatusCode:             int32(res.StatusCode),
		ServerName:             res.Header.Get("Server"),
		ResContentEncoding:     res.Header.Get("Content-Encoding"),
		ResContentTypeDetected: detected,
		ResCookies:             readCookies(res.Cookies()),
		ResponseHeader:         readHeader(res.Header),
	}
}

func readHeader(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, vals := range h {
		m[k] = strings.Join(vals, " ")
	}
	return m
}

func readParameters(h url.Values) map[string]string {
	m := make(map[string]string)
	for k, vals := range h {
		m[k] = strings.Join(vals, " ")
	}
	return m
}