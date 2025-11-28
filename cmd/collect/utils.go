/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
