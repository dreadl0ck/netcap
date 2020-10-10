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
	"testing"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

var tcps = []*types.TCP{
	{
		Timestamp:   utils.StringToTime("1505838533.449164").UnixNano(),
		SrcPort:     443,
		DstPort:     49209,
		SeqNum:      2765430390,
		AckNum:      1629385951,
		DataOffset:  5,
		SYN:         true,
		Window:      179,
		Checksum:    62474,
		PayloadSize: 5,
		SrcIP:       "192.168.1.14",
		DstIP:       "172.217.6.163",
	},
	{
		Timestamp:   utils.StringToTime("1505838533.459141").UnixNano(),
		SrcPort:     49209,
		DstPort:     443,
		SeqNum:      2765430393,
		AckNum:      1629385954,
		DataOffset:  6,
		SYN:         true,
		ACK:         true,
		Window:      179,
		Checksum:    62473,
		PayloadSize: 3,
		SrcIP:       "172.217.6.163",
		DstIP:       "192.168.1.14",
	},
	{
		Timestamp:   utils.StringToTime("1505838533.479163").UnixNano(),
		SrcPort:     443,
		DstPort:     49209,
		SeqNum:      2765430390,
		AckNum:      1629385951,
		DataOffset:  5,
		ACK:         true,
		Window:      179,
		Checksum:    62412,
		PayloadSize: 15,
		SrcIP:       "192.168.1.14",
		DstIP:       "172.217.6.163",
	},
}

func TestWriter(t *testing.T) {
	// create a new writer
	w := newProtoWriter(&WriterConfig{
		Proto:                true,
		Name:                 "TCP-writer-test",
		Buffer:               true,
		Compress:             true,
		Out:                  "../tests",
		MemBufferSize:        defaults.BufferSize,
		Source:               "unit tests",
		Version:              netcap.Version,
		IncludesPayloads:     false,
		StartTime:            time.Now(),
		CompressionBlockSize: defaults.CompressionBlockSize,
	})
	if w == nil {
		t.Fatal("got nil writer")
	}

	// write netcap header
	err := w.WriteHeader(types.Type_NC_TCP)
	if err != nil {
		t.Fatal(err)
	}

	// write into writer
	for _, tcp := range tcps {
		err = w.Write(tcp)
		if err != nil {
			t.Fatal(err)
		}
	}

	// close and flush
	_, size := w.Close(int64(len(tcps)))
	if size == 0 {
		t.Fatal("no bytes written")
	}
}

func BenchmarkWriter(b *testing.B) {
	// create a new writer
	w := newProtoWriter(&WriterConfig{
		Proto:                true,
		Name:                 "TCP-writer-test",
		Buffer:               true,
		Compress:             true,
		Out:                  "../tests",
		MemBufferSize:        defaults.BufferSize,
		Source:               "unit tests",
		Version:              netcap.Version,
		IncludesPayloads:     false,
		StartTime:            time.Now(),
		CompressionBlockSize: defaults.CompressionBlockSize,
	})
	if w == nil {
		b.Fatal("got nil writer")
	}

	// write netcap header
	err := w.WriteHeader(types.Type_NC_TCP)
	if err != nil {
		b.Fatal(err)
	}

	tcp := tcps[0]

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		// write into writer
		err = w.Write(tcp)
		if err != nil {
			b.Fatal(err)
		}
	}

	// close and flush
	_, size := w.Close(int64(b.N))
	if size < 1 {
		b.Fatal("no data written")
	}
}
