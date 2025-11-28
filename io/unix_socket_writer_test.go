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
