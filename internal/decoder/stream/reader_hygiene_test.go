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
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tls"
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
	messages   []proto.Message

	// contradictions counts records that say IsResponse and then name the
	// client as their source. A record type carrying that field models one
	// message rather than a transaction, so the decoder already knows which
	// way the message went.
	contradictions int
	hasIsResponse  bool
	responses      int
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
		t.Fatalf("%s: reader factory missing", s.decoder)
	}

	writer := &captureWriter{}

	previous := sd.Writer
	sd.Writer = writer

	defer func() { sd.Writer = previous }()
	if s.decoder == "TLSCertificate" {
		tls.ResetCertificates()
		defer tls.ResetCertificates()
	}
	if s.decoder == "SMTP" || s.decoder == "POP3" {
		if err := sd.PostInitFunc(); err != nil {
			t.Fatalf("%s logger initialization: %v", s.decoder, err)
		}
	}

	// Both directions present, each carrying its own bytes twice so a reader
	// that frames per direction has more than one record to place in time.
	const (
		clientFirst  = int64(1_000_000_000)
		clientSecond = int64(5_000_000_000)
		serverFirst  = int64(3_000_000_000)
	)

	clientBytes, serverBytes := readerFixture(t, s)
	client := core.DataFragments{
		hygieneFragment(clientBytes, clientFirst, false),
		hygieneFragment(clientBytes, clientSecond, false),
	}

	server := core.DataFragments{}
	if len(serverBytes) > 0 {
		server = append(server, hygieneFragment(serverBytes, serverFirst, true))
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

	sd.Factory.New(conv).Decode()
	if s.decoder == "TLSCertificate" {
		if tls.GetCertificateCount() == 0 {
			t.Fatal("TLS certificate handshake yielded no parsed certificate")
		}
		if err := sd.DeInitFunc(); err != nil {
			t.Fatalf("flushing parsed TLS certificates: %v", err)
		}
	}

	report := readerReport{decoder: s.decoder, records: len(writer.records), messages: writer.records}

	seenTS := map[int64]bool{}
	seenIP := map[string]bool{}

	for _, rec := range writer.records {
		if f, ok := field(rec, "Timestamp"); ok && f.Kind() == reflect.Int64 {
			seenTS[f.Int()] = true
		}

		src := ""
		if f, ok := field(rec, "SrcIP"); ok && f.Kind() == reflect.String {
			src = f.String()
			seenIP[src] = true
		}

		// A record that says it is a response and names the client as its
		// source contradicts itself.
		if f, ok := field(rec, "IsResponse"); ok && f.Kind() == reflect.Bool {
			report.hasIsResponse = true

			if f.Bool() {
				report.responses++
				if src == conv.ClientIP {
					report.contradictions++
				}
			}
		}
	}

	report.timestamps = len(seenTS)

	for ip := range seenIP {
		report.srcIPs = append(report.srcIPs, ip)
	}

	sort.Strings(report.srcIPs)

	return report, true
}

func readerFixture(t *testing.T, s sample) (clientBytes, serverBytes []byte) {
	t.Helper()
	clientBytes, serverBytes = s.client, s.server
	if s.readerClient != nil {
		clientBytes = s.readerClient
	}
	if s.readerServer != nil {
		serverBytes = s.readerServer
	}
	switch s.decoder {
	case "TLSCertificate":
		serverBytes = append(tlsHello(2), certificateHandshake(t)...)
	case "QUICClientHello":
		clientBytes = capturedQUICClientHello(t)
	}
	return clientBytes, serverBytes
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
// Coverage is asserted for all 29 readers. One timestamp in a transaction
// summary is valid; message readers that emit multiple records are checked for
// distinct times in TestEveryStreamReaderEmitsItsOwnAuditRecord.
func TestReaderTimestampAndDirectionHygiene(t *testing.T) {
	matchingEnv(t)

	var (
		rows           []string
		singleTS       []string
		clientOnly     []string
		droveSomething int
	)

	for _, s := range samples() {
		report, _ := driveReader(t, s)
		if report.records == 0 {
			t.Errorf("%s: matching sample selected a decoder but its reader emitted no records", s.decoder)
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
	if droveSomething != len(registeredDecoders()) {
		t.Errorf("exercised %d of %d registered stream readers", droveSomething, len(registeredDecoders()))
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

// A record that carries IsResponse describes one message, and the decoder set
// that field, so it knows the direction. Naming the client as the source of a
// response contradicts the record's own contents.
//
// This asserts rather than reports: it is not a judgement about how a reader
// should model a conversation, it is a record disagreeing with itself.
func TestResponseRecordsAreNotAttributedToTheClient(t *testing.T) {
	matchingEnv(t)

	for _, s := range samples() {
		report, _ := driveReader(t, s)
		if !report.hasIsResponse || report.records == 0 {
			continue
		}

		t.Run(s.decoder, func(t *testing.T) {
			if (s.decoder == "SMB" || s.decoder == "FTP" || s.decoder == "IMAP") && report.responses == 0 {
				t.Fatal("the two-direction fixture produced no response; the direction check cannot run")
			}
			if report.contradictions > 0 {
				t.Errorf("%d of %d records say IsResponse and name the client as their source",
					report.contradictions, report.records)
			}
		})
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

func TestEveryStreamReaderEmitsItsOwnAuditRecord(t *testing.T) {
	matchingEnv(t)
	for _, s := range samples() {
		t.Run(s.decoder, func(t *testing.T) {
			report, _ := driveReader(t, s)
			if report.records == 0 {
				t.Fatal("signature matched, but reader wrote no audit record")
			}
			for _, msg := range report.messages {
				r, ok := msg.(types.AuditRecord)
				if !ok || r.NetcapType() != DefaultRecordType(s.decoder) {
					t.Fatalf("%s reader wrote unexpected record %T", s.decoder, msg)
				}
				if r.Time() <= 0 {
					t.Errorf("%s record has no capture timestamp", s.decoder)
				}
			}
			switch s.decoder {
			case "SMTP":
				if len(report.messages[0].(*types.SMTP).Commands) == 0 {
					t.Fatal("SMTP summary has no parsed commands")
				}
			case "POP3":
				if len(report.messages[0].(*types.POP3).Commands) == 0 {
					t.Fatal("POP3 summary has no parsed commands")
				}
			case "TLSCertificate":
				cert := report.messages[0].(*types.TLSCertificate)
				if cert.Timestamp != 3_000_000_000 || len(cert.SubjectAltNames) == 0 || cert.SrcIP != "192.0.2.2" {
					t.Fatalf("TLS certificate lacks server time, identity or direction: %+v", cert)
				}
			case "SMB":
				response := false
				for _, msg := range report.messages {
					r := msg.(*types.SMB)
					response = response || r.IsResponse && r.SrcIP == "192.0.2.2" && r.Timestamp == 3_000_000_000
				}
				if !response || report.timestamps < 2 {
					t.Fatalf("SMB request/response not attributed to distinct times and peers: %+v", report)
				}
			case "IPP", "Zabbix":
				if report.timestamps < 2 {
					t.Errorf("%s emitted %d records at %d distinct times", s.decoder, report.records, report.timestamps)
				}
				if s.decoder == "IPP" && report.messages[0].(*types.IPP).RequestID != 1 {
					t.Fatal("IPP reader did not parse the request ID")
				}
				if s.decoder == "Zabbix" && report.messages[0].(*types.Zabbix).Key != "agent.ping" {
					t.Fatal("Zabbix reader did not parse the JSON payload")
				}
			case "CIP":
				response := false
				for _, msg := range report.messages {
					r := msg.(*types.CIP)
					response = response || r.Response && r.SrcIP == "192.0.2.2" && r.Timestamp == 3_000_000_000
				}
				if !response {
					t.Fatal("CIP response missing or attributed to the initiating client")
				}
			case "QUICClientHello":
				r := report.messages[0].(*types.QUICClientHello)
				if r.SNI == "" && len(r.CipherSuites) == 0 {
					t.Fatal("QUIC reader wrote a record with no decoded ClientHello")
				}
			}
		})
	}
}

func DefaultRecordType(name string) types.Type {
	for _, port := range SortedDecoderPorts {
		if sd := DefaultStreamDecoders[port]; sd.GetName() == name {
			return sd.GetType()
		}
	}
	for _, sd := range UDPStreamDecoders {
		if sd.GetName() == name {
			return sd.GetType()
		}
	}
	return types.Type_NC_Header
}
