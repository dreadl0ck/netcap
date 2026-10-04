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

package netio

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

// Concatenated channel messages behind a header must read back as a valid
// record stream: each message is exactly one delimited record.
func TestChanWriterEmitsDelimitedRecords(t *testing.T) {
	w := newChanWriter(&WriterConfig{Name: "TCP", Type: types.Type_NC_TCP, Chan: true, ChanSize: len(tcps)})

	if err := w.WriteHeader(types.Type_NC_TCP); err != nil {
		t.Fatal(err)
	}
	for _, r := range tcps {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	w.Close(int64(len(tcps)))

	var buf bytes.Buffer
	dw := delimited.NewWriter(&buf)
	if err := dw.PutProto(NewHeader(types.Type_NC_TCP, "test", "v", false, time.Unix(0, tcps[0].Timestamp))); err != nil {
		t.Fatal(err)
	}
	msgs := 0
	for m := range w.GetChan() {
		buf.Write(m)
		msgs++
	}
	if msgs != len(tcps) {
		t.Fatalf("got %d channel messages, want %d (header must not be sent)", msgs, len(tcps))
	}

	r := delimited.NewReader(&buf)
	var hdr types.Header
	if err := r.NextProto(&hdr); err != nil || hdr.Type != types.Type_NC_TCP {
		t.Fatalf("header: %v %v", err, hdr.Type)
	}
	for i, want := range tcps {
		var got types.TCP
		if err := r.NextProto(&got); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if got.SeqNum != want.SeqNum || got.SrcIP != want.SrcIP {
			t.Fatalf("record %d mismatch: %+v", i, &got)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing data: %v", err)
	}
}

func TestChanWriterCloseIsIdempotentAndRejectsWrites(t *testing.T) {
	w := newChanWriter(&WriterConfig{Name: "TCP", Type: types.Type_NC_TCP, Chan: true, ChanSize: 1})
	w.Close(0)
	w.Close(0)
	if err := w.Write(tcps[0]); !errors.Is(err, ErrChanWriterClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestSharedWriterExposesChan(t *testing.T) {
	ResetWriterRegistry()
	defer ResetWriterRegistry()

	wc := &WriterConfig{Name: "Shared", Type: types.Type_NC_TCP, Chan: true, ChanSize: 1}
	a := GetSharedAuditRecordWriter(wc).(ChannelAuditRecordWriter)
	b := GetSharedAuditRecordWriter(wc).(ChannelAuditRecordWriter)
	if a.GetChan() == nil || a.GetChan() != b.GetChan() {
		t.Fatal("shared writers must expose one non-nil channel")
	}
}
