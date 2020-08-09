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

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

// sendUDP wraps the whole functionality of a UDP client that sends
// a message and currently does not wait for a reply.
func sendUDP(ctx context.Context, address string, reader io.Reader) error {
	// in case a hostname is specified
	// resolve the UDP address so that we can make use of DialUDP
	// with an actual IP and port instead of a name
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	// Although we're not in a connection-oriented transport,
	// the act of `dialing` is analogous to the act of performing
	// a `connect(2)` syscall for a socket of type SOCK_DGRAM:
	// - it forces the underlying socket to only read and write
	//   to and from a specific remote address.
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}

	// Closes the underlying file descriptor associated with the,
	// socket so that it no longer refers to any file.
	defer func() {
		errClose := conn.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	var (
		doneChan = make(chan error, 1)
		n        int64
	)

	go func() {
		// It is possible that this action blocks, although this
		// should only occur in very resource-intensive situations:
		// - when you've filled up the socket buffer and the OS
		//   can't dequeue the queue fast enough.
		n, err = io.Copy(conn, reader)
		if err != nil {
			doneChan <- err

			return
		}

		fmt.Printf("packet-written: bytes=%d\n", n)

		// dont wait for a reply for now
		doneChan <- nil
	}()

	select {
	case <-ctx.Done():
		fmt.Println("canceled")

		err = ctx.Err()
	case err = <-doneChan:
	}

	return err
}
