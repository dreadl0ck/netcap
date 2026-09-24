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

package stream

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// captureWriter collects records instead of writing them to disk.
type captureWriter struct {
	netio.AuditRecordWriter

	records []proto.Message
}

func (w *captureWriter) Write(msg proto.Message) error {
	w.records = append(w.records, proto.Clone(msg))

	return nil
}

func (w *captureWriter) WriteHeader(types.Type) error { return nil }
func (w *captureWriter) Flush() error                 { return nil }

// hygieneFragment is one direction's bytes with its own capture time.
func hygieneFragment(data []byte, ts int64, server bool) *core.StreamData {
	d := &core.StreamData{
		RawData:            data,
		CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, ts)},
	}
	if server {
		d.Dir = reassembly.TCPDirServerToClient
	}

	return d
}

// field reads a named field from an audit record by reflection, so one harness
// can inspect 29 different record types.
func field(msg proto.Message, name string) (reflect.Value, bool) {
	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}

	f := v.FieldByName(name)

	return f, f.IsValid()
}

// readerReport is what driving one decoder with a two-sided conversation
// revealed.
type readerReport struct {
	decoder    string
	records    int
	timestamps int
	srcIPs     []string
}

// driveReader runs one decoder over a conversation whose two directions carry
// different bytes at clearly different times.
func driveReader(t *testing.T, s sample) (readerReport, bool) {
	t.Helper()

	var sd *decoder.StreamDecoder

	for _, port := range SortedDecoderPorts {
		if api := DefaultStreamDecoders[port]; api.GetName() == s.decoder {
			if d, ok := api.(*decoder.StreamDecoder); ok {
				sd = d
			}

			break
		}
	}

	if sd == nil {
		for _, api := range UDPStreamDecoders {
			if api.GetName() == s.decoder {
				if d, ok := api.(*decoder.StreamDecoder); ok {
					sd = d
				}

				break
			}
		}
	}

	if sd == nil || sd.Factory == nil {
		return readerReport{}, false
	}

	writer := &captureWriter{}

	previous := sd.Writer
	sd.Writer = writer

	defer func() { sd.Writer = previous }()

	// Both directions present, each carrying its own bytes twice so a reader
	// that frames per direction has more than one record to place in time.
	const (
		clientFirst  = int64(1_000_000_000)
		clientSecond = int64(5_000_000_000)
		serverFirst  = int64(3_000_000_000)
	)

	client := core.DataFragments{
		hygieneFragment(s.client, clientFirst, false),
		hygieneFragment(s.client, clientSecond, false),
	}

	server := core.DataFragments{}
	if len(s.server) > 0 {
		server = append(server, hygieneFragment(s.server, serverFirst, true))
	}

	merged := core.DataFragments{}
	merged = append(merged, client...)
	merged = append(merged, server...)

	conv := &core.ConversationInfo{
		Data: merged, ClientData: client, ServerData: server,
		Ident:    "hygiene",
		ClientIP: "192.0.2.1", ServerIP: "192.0.2.2",
		ClientPort: 12345, ServerPort: s.port,
		CommunityID:          "community",
		TCPHandshakeComplete: true,
		FirstClientPacket:    time.Unix(0, clientFirst),
		FirstServerPacket:    time.Unix(0, serverFirst),
	}

	func() {
		// A reader panicking on synthetic input is itself a finding, but it
		// must not take the suite down.
		defer func() { _ = recover() }()

		sd.Factory.New(conv).Decode()
	}()

	report := readerReport{decoder: s.decoder, records: len(writer.records)}

	seenTS := map[int64]bool{}
	seenIP := map[string]bool{}

	for _, rec := range writer.records {
		if f, ok := field(rec, "Timestamp"); ok && f.Kind() == reflect.Int64 {
			seenTS[f.Int()] = true
		}

		if f, ok := field(rec, "SrcIP"); ok && f.Kind() == reflect.String {
			seenIP[f.String()] = true
		}
	}

	report.timestamps = len(seenTS)

	for ip := range seenIP {
		report.srcIPs = append(report.srcIPs, ip)
	}

	sort.Strings(report.srcIPs)

	return report, true
}

// Reports which readers collapse a conversation to a single timestamp and which
// attribute every record to the client.
//
// Both are the defects the DNP3 decoder was rewritten to remove. A reader that
// merges conversation.Data into one buffer and stamps every record with
// FirstClientPacket loses the direction -- a response becomes indistinguishable
// from a command -- and collapses a connection held open for days into one
// instant, which makes any question about ordering or a maintenance window
// unanswerable.
//
// This reports rather than asserts: 17 of 29 readers are in this state, and
// converting them is a change per reader, not a change here.
func TestReaderTimestampAndDirectionHygiene(t *testing.T) {
	matchingEnv(t)

	var (
		rows           []string
		singleTS       []string
		clientOnly     []string
		droveSomething int
	)

	for _, s := range samples() {
		report, ok := driveReader(t, s)
		if !ok || report.records == 0 {
			continue
		}

		droveSomething++

		verdict := "ok"

		if report.records > 1 && report.timestamps == 1 {
			verdict = "one timestamp for every record"

			singleTS = append(singleTS, s.decoder)
		}

		if len(s.server) > 0 && len(report.srcIPs) == 1 && report.srcIPs[0] == "192.0.2.1" {
			if verdict == "ok" {
				verdict = "client attributed to every record"
			} else {
				verdict += "; client attributed to every record"
			}

			clientOnly = append(clientOnly, s.decoder)
		}

		rows = append(rows, fmt.Sprintf("%-16s records=%-4d timestamps=%-4d src=%-28v %s",
			s.decoder, report.records, report.timestamps, report.srcIPs, verdict))
	}

	t.Log("reader timestamp and direction hygiene:\n" + strings.Join(rows, "\n"))
	t.Logf("drove %d readers; %d collapse to one timestamp, %d attribute every record to the client",
		droveSomething, len(singleTS), len(clientOnly))

	if len(singleTS) > 0 {
		t.Logf("single timestamp: %v", singleTS)
	}

	if len(clientOnly) > 0 {
		t.Logf("client-attributed only: %v", clientOnly)
	}
}

// The decoders already converted must not regress.
//
// dnp3 and modbus frame each direction separately and timestamp each record
// from the packet that carried it. Both were rewritten for exactly that, so
// losing it would be a silent return to the original defect.
var readersWithPerFrameTiming = []string{"DNP3", "Modbus"}

func TestConvertedReadersKeepPerFrameTiming(t *testing.T) {
	matchingEnv(t)

	for _, name := range readersWithPerFrameTiming {
		t.Run(name, func(t *testing.T) {
			var found *sample

			for _, s := range samples() {
				if s.decoder == name {
					found = &s

					break
				}
			}

			if found == nil {
				t.Fatalf("no sample for %s", name)
			}

			report, ok := driveReader(t, *found)
			if !ok {
				t.Fatalf("could not drive %s", name)
			}

			if report.records < 2 {
				t.Fatalf("got %d records from two fragments, need at least 2 to test timing", report.records)
			}

			if report.timestamps < 2 {
				t.Errorf("%d records share %d timestamp(s): per-frame timing has been lost",
					report.records, report.timestamps)
			}
		})
	}
}
