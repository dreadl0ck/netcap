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

package proxy

import (
	"github.com/namsral/flag"
	"os"
)

func Flags() (flags []string) {
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, f.Name)
	})
	return
}

// flags
var (
	fs                      = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagDialTimeout         = fs.Int("dialTimeout", 30, "seconds until dialing to the backend times out")
	flagIdleConnTimeout     = fs.Int("idleConnTimeout", 90, "seconds until a connection times out")
	flagTLSHandshakeTimeout = fs.Int("tlsTimeout", 15, "seconds until a TLS handshake times out")
	flagSkipTLSVerify       = fs.Bool("skipTlsVerify", false, "skip TLS verification")
	flagMaxIdleConns        = fs.Int("maxIdle", 120, "maximum number of idle connections")
	flagLocal               = fs.String("local", "", "set local endpoint")
	flagConfig              = fs.String("config", "net.proxy-config.yml", "set config file path")
	flagRemote              = fs.String("remote", "", "set remote endpoint")
	flagDebug               = fs.Bool("debug", false, "set debug mode")
	flagTrace               = fs.Bool("trace", true, "trace HTTP requests to retrieve additional information")
	flagDump                = fs.Bool("dump", false, "dumps audit record as JSON to stdout")
	flagDumpFormatted       = fs.Bool("format", true, "format when dumping JSON")
	flagVersion             = fs.Bool("version", false, "print netcap package version and exit")
	flagMemBufferSize       = fs.Int("membuf-size", 1024*1024*10, "set size for membuf")
)
