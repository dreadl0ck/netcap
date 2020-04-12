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

package netcap

import (
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestWriter(t *testing.T) {

	// create a new writer
	w := NewWriter("TCP-writer-test", true, true, false, "tests", false, 1024*1024*10)

	var tcps = []*types.TCP{
		{
			Timestamp:      "",
			SrcPort:        0,
			DstPort:        0,
			SeqNum:         0,
			AckNum:         0,
			DataOffset:     0,
			FIN:            false,
			SYN:            false,
			RST:            false,
			PSH:            false,
			ACK:            false,
			URG:            false,
			ECE:            false,
			CWR:            false,
			NS:             false,
			Window:         0,
			Checksum:       0,
			Urgent:         0,
			Padding:        nil,
			Options:        nil,
			PayloadEntropy: 0,
			PayloadSize:    0,
			Payload:        nil,
			Context:        nil,
		},
		{
			Timestamp:      "",
			SrcPort:        0,
			DstPort:        0,
			SeqNum:         0,
			AckNum:         0,
			DataOffset:     0,
			FIN:            false,
			SYN:            false,
			RST:            false,
			PSH:            false,
			ACK:            false,
			URG:            false,
			ECE:            false,
			CWR:            false,
			NS:             false,
			Window:         0,
			Checksum:       0,
			Urgent:         0,
			Padding:        nil,
			Options:        nil,
			PayloadEntropy: 0,
			PayloadSize:    0,
			Payload:        nil,
			Context:        nil,
		},
		{
			Timestamp:      "",
			SrcPort:        0,
			DstPort:        0,
			SeqNum:         0,
			AckNum:         0,
			DataOffset:     0,
			FIN:            false,
			SYN:            false,
			RST:            false,
			PSH:            false,
			ACK:            false,
			URG:            false,
			ECE:            false,
			CWR:            false,
			NS:             false,
			Window:         0,
			Checksum:       0,
			Urgent:         0,
			Padding:        nil,
			Options:        nil,
			PayloadEntropy: 0,
			PayloadSize:    0,
			Payload:        nil,
			Context:        nil,
		},
		{
			Timestamp:      "",
			SrcPort:        0,
			DstPort:        0,
			SeqNum:         0,
			AckNum:         0,
			DataOffset:     0,
			FIN:            false,
			SYN:            false,
			RST:            false,
			PSH:            false,
			ACK:            false,
			URG:            false,
			ECE:            false,
			CWR:            false,
			NS:             false,
			Window:         0,
			Checksum:       0,
			Urgent:         0,
			Padding:        nil,
			Options:        nil,
			PayloadEntropy: 0,
			PayloadSize:    0,
			Payload:        nil,
			Context:        nil,
		},
	}

	// write netcap header
	err := w.WriteHeader(types.Type_NC_TCP, "unit tests", Version, false)
	if err != nil {
		t.Fatal(err)
	}

	// write into writer
	for _, tcp := range tcps {
		err := w.Write(tcp)
		if err != nil {
			t.Fatal(err)
		}
	}

	// close and flush
	_, size := w.Close()
	if size < 1 {
		t.Fatal("no data written")
	}
}
