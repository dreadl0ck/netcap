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

package collect

import (
	"os"

	"github.com/namsral/flag"

	"github.com/dreadl0ck/netcap/defaults"
)

// Flags returns all flags.
func Flags() (flags []string) {
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, f.Name)
	})

	return
}

var (
	fs                 = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenerateConfig = fs.Bool("gen-config", false, "generate config")
	_                  = fs.String("config", "", "read configuration from file at path")
	flagGenKeypair     = fs.Bool("gen-keypair", false, "generate keypair")
	flagPrivKey        = fs.String("privkey", "", "path to the hex encoded server private key")
	flagAddr           = fs.String("addr", "127.0.0.1:1335", "specify an address and port to listen for incoming traffic")

	files             = make(map[string]*auditRecordHandle)
	flagMemBufferSize = fs.Int("membuf-size", defaults.BufferSize, "set size for membuf")

	// not configurable at the moment
	// flagCompress   = flag.Bool("comp", true, "compress data when writing to disk")
	// flagBuffer     = flag.Bool("buf", true, "buffer data before writing to disk").
)
