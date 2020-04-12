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

package collect

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
	fs                = flag.NewFlagSetWithEnvPrefix(os.Args[0], "NC", flag.ExitOnError)
	flagGenKeypair    = fs.Bool("gen-keypair", false, "generate keypair")
	flagPrivKey       = fs.String("privkey", "", "path to the hex encoded server private key")
	flagAddr          = fs.String("addr", "127.0.0.1:1335", "specify an adress and port to listen for incoming traffic")
	flagVersion       = fs.Bool("version", false, "print netcap package version and exit")
	files             = make(map[string]*AuditRecordHandle)
	flagMemBufferSize = fs.Int("membuf-size", 1024*1024*10, "set size for membuf")

	// not configurable at the moment
	// flagCompress   = flag.Bool("comp", true, "compress data when writing to disk")
	// flagBuffer     = flag.Bool("buf", true, "buffer data before writing to disk")
)
