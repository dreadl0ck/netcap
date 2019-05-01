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
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	// Debug mode
	Debug bool
)

func cleanup() {
	for _, p := range proxies {
		p.writer.Close()
	}
}

func handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// start signal handler and cleanup routine
	go func() {
		sig := <-sigs

		fmt.Println("received signal:", sig)

		fmt.Println("exiting")

		cleanup()
		os.Exit(0)
	}()
}

// TrimPortIPv4 trims the port number from an IPv4 address string
func TrimPortIPv4(addr string) string {
	slice := strings.Split(addr, ":")
	if len(slice) == 2 {
		return slice[0]
	}
	return addr
}

// DumpHTTPResponse dumps an http.Response for debugging purposes
func DumpHTTPResponse(resp *http.Response, proxyName string, rawbody []byte) {

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

// DumpHTTPRequest dumps an http.Request for debugging purposes
func DumpHTTPRequest(req *http.Request, proxyName string) {

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
