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

package distributed

import (
	"bytes"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// FuzzReadFrame: arbitrary input never panics and never yields a payload
// over the limit.
func FuzzReadFrame(f *testing.F) {
	var ok bytes.Buffer
	_ = WriteFrame(&ok, FrameBatch, []byte("hello"))
	f.Add(ok.Bytes())
	f.Add([]byte{FrameBatch, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		for {
			_, p, err := ReadFrame(r, 1024)
			if err != nil {
				return
			}
			if len(p) > 1024 {
				t.Fatalf("payload of %d bytes over limit", len(p))
			}
		}
	})
}

// FuzzBatchDecode runs the collector's decode and validation path on
// arbitrary frame payloads: it must reject or accept, never panic.
func FuzzBatchDecode(f *testing.F) {
	good, _ := proto.Marshal(&types.Batch{MessageType: types.Type_NC_TCP, Seq: 1, Data: delimitedTCP(f, 3)})
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add([]byte{0x22, 0xff, 0xff, 0xff, 0x0f})

	f.Fuzz(func(_ *testing.T, in []byte) {
		b := new(types.Batch)
		if err := proto.Unmarshal(in, b); err != nil {
			return
		}
		_, _ = CountRecords(b.MessageType, b.Data)
	})
}
