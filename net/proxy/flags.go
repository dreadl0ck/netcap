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

// flags
var (
	flagDialTimeout         int // = flag.Int("dialTimeout", 30, "seconds until dialing to the backend times out")
	flagIdleConnTimeout     int // = flag.Int("idleConnTimeout", 90, "seconds until a connection times out")
	flagTLSHandshakeTimeout int // = flag.Int("tlsTimeout", 15, "seconds until a TLS handshake times out")
	flagSkipTLSVerify       bool // = flag.Bool("skipTlsVerify", false, "skip TLS verification")
	flagMaxIdleConns        int // = flag.Int("maxIdle", 120, "maximum number of idle connections")
	flagLocal               string // = flag.String("local", "", "set local endpoint")
	flagConfig              string // = flag.String("config", "net.proxy-config.yml", "set config file path")
	flagRemote              string // = flag.String("remote", "", "set remote endpoint")
	flagDebug               bool // = flag.Bool("debug", false, "set debug mode")
	flagTrace               bool // = flag.Bool("trace", true, "trace HTTP requests to retrieve additional information")
	flagDump                bool // = flag.Bool("dump", false, "dumps audit record as JSON to stdout")
	flagDumpFormatted       bool // = flag.Bool("format", true, "format when dumping JSON")
	flagVersion             bool // = flag.Bool("version", false, "print netcap package version and exit")
)
