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

package collector

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/types"
)

type chanPacketDecoder struct {
	packet.DecoderAPI
	ch chan []byte
}

func (d chanPacketDecoder) GetChan() <-chan []byte { return d.ch }
func (chanPacketDecoder) GetType() types.Type      { return types.Type_NC_Ethernet }

type chanStreamDecoder struct {
	core.StreamDecoderAPI
	ch chan []byte
}

func (d chanStreamDecoder) GetChan() <-chan []byte { return d.ch }
func (chanStreamDecoder) GetType() types.Type      { return types.Type_NC_HTTP }

type chanAbstractDecoder struct {
	core.DecoderAPI
	ch chan []byte
}

func (d chanAbstractDecoder) GetChan() <-chan []byte { return d.ch }
func (chanAbstractDecoder) GetType() types.Type      { return types.Type_NC_Connection }

// Stream and abstract decoders were left out of batching, so their channels
// filled and blocked the decoder. Shared writers must yield one channel.
func TestBatchChannelsIncludesEveryDecoderKindOnce(t *testing.T) {
	var (
		pch, sch, ach = make(chan []byte), make(chan []byte), make(chan []byte)
		c             = &Collector{}
	)
	c.packetDecoders = []packet.DecoderAPI{chanPacketDecoder{ch: pch}, chanPacketDecoder{}}
	c.streamDecoders = []core.StreamDecoderAPI{chanStreamDecoder{ch: sch}, chanStreamDecoder{ch: sch}}
	c.abstractDecoders = []core.DecoderAPI{chanAbstractDecoder{ch: ach}}

	got := map[types.Type]int{}
	for _, bi := range c.batchChannels() {
		got[bi.Type]++
	}
	want := map[types.Type]int{types.Type_NC_Ethernet: 1, types.Type_NC_HTTP: 1, types.Type_NC_Connection: 1}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
