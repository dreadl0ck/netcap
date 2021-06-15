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

package io

import (
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestUNIXSocket(t *testing.T) {

	// Create unix socket
	path := "/tmp/test.sock"
	if err := os.RemoveAll(path); err != nil {
		log.Fatal(err)
	}

	raddr, err := net.ResolveUnixAddr(networkTypeUnixgram, path)
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.ListenUnixgram(networkTypeUnixgram, raddr)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	fmt.Println("listening for incoming alerts on UNIX socket at", path)

	done := make(chan bool)
	count := 0
	expected := 1000

	go func() {
		for {
			var buf = make([]byte, 1024)
			_, err := l.Read(buf)
			if err != nil {
				log.Println("failed to read from UNIX socket", err)
				return
			}
			//fmt.Println("read from UNIX socket", string(buf[:n]))

			count++
			if count == expected {
				done <- true
			}

		}
	}()

	time.Sleep(1 + time.Second)

	// connect as client to socket
	s := createUnixSocket("test")

	for i := 0; i < 1000; i++ {
	again:
		_, err := s.Write([]byte("test"))
		if err != nil {
			goto again
		}
	}

	<-done
}
