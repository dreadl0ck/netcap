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

package util

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

var (
	// util
	fs                = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagCheckFields   = fs.Bool("check", false, "check number of occurences of the separator, in fields of an audit record file")
	flagToUTC         = fs.String("ts2utc", "", "util to convert seconds.microseconds timestamp to UTC")
	flagInput         = fs.String("read", "", "read specified file, can either be a pcap or netcap audit record file")
	flagSeparator     = fs.String("sep", ",", "set separator string for csv output")
	flagVersion       = fs.Bool("version", false, "print netcap package version and exit")
	flagMemBufferSize = fs.Int("membuf-size", 1024*1024*10, "set size for membuf")
)
