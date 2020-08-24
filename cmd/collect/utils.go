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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dreadl0ck/netcap/io"
)

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("collect tool usage examples:")
	fmt.Println("	$ net collect -privkey priv.key -addr 127.0.0.1:4200")
	fmt.Println("	$ net collect -gen-keypair")
	fmt.Println()
}

// usage prints the use.
func printUsage() {
	printHeader()
	fs.PrintDefaults()
}

func cleanup() {
	fmt.Println("cleanup")

	// cleanup
	for p, a := range files { // flush and close gzip writer
		err := a.gWriter.Flush()
		if err != nil {
			panic(err)
		}

		err = a.gWriter.Close()
		if err != nil {
			panic(err)
		}

		// flush buffered writer
		err = a.bWriter.Flush()
		if err != nil {
			panic(err)
		}

		// sync and close file handle
		fmt.Println("closing file", p)
		err = a.f.Sync()
		if err != nil {
			panic(err)
		}
		err = a.f.Close()
		if err != nil {
			panic(err)
		}
	}
}

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
