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
	"net"
	"os"
	"testing"
	"time"
)

func TestUNIXSocket(t *testing.T) {

	// Create unix socket
	path := "/tmp/test.sock"
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}

	raddr, err := net.ResolveUnixAddr(networkTypeUnixgram, path)
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.ListenUnixgram(networkTypeUnixgram, raddr)
	if err != nil {
		t.Fatal("listen error:", err)
	}
	defer l.Close()

	t.Log("listening for incoming alerts on UNIX socket at", path)

	done := make(chan bool, 1)
	count := 0
	expected := 1000

	go func() {
		for {
			var buf = make([]byte, 1024)
			_, err := l.Read(buf)
			if err != nil {
				// listener was closed, exit gracefully
				return
			}

			count++
			if count == expected {
				done <- true
				return
			}
		}
	}()

	time.Sleep(1 * time.Second)

	// connect as client to socket
	s := createUnixSocket("test")
	defer s.Close()

	const maxRetries = 10
	for i := range 1000 {
		var writeErr error
		for retry := 0; retry < maxRetries; retry++ {
			_, writeErr = s.Write([]byte("test"))
			if writeErr == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if writeErr != nil {
			t.Fatalf("failed to write message %d after %d retries: %v", i, maxRetries, writeErr)
		}
	}

	select {
	case <-done:
		t.Log("received all", expected, "messages")
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %d messages, only received %d", expected, count)
	}
}
