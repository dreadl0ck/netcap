package stream

import (
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/modbus"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/quic"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tls"
	"github.com/dreadl0ck/netcap/types"
)

func matchingSample(t *testing.T, name string) sample {
	t.Helper()
	for _, s := range samples() {
		if s.decoder == name {
			return s
		}
	}
	t.Fatalf("missing %s fixture", name)
	return sample{}
}

func TestSelectionHonorsIncludedAndExcludedDecoders(t *testing.T) {
	matchingEnv(t)
	dnp3 := matchingSample(t, "DNP3")
	modbus := matchingSample(t, "Modbus")
	for _, tc := range []struct {
		name, include, exclude, expected string
		traffic                          sample
	}{
		{"exclude decoder on its own port", "", "DNP3", "", dnp3},
		{"include only another decoder", "Modbus", "", "", dnp3},
		{"include decoder on its own port", "DNP3", "", "DNP3", dnp3},
		{"excluded fallback decoder", "", "Modbus", "", modbus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoderconfig.Instance.IncludeDecoders = tc.include
			decoderconfig.Instance.ExcludeDecoders = tc.exclude
			sel, ok := selectFor(tc.traffic, core.TCP, tc.traffic.port)
			if got := winner(sel, ok); (tc.expected == "" && ok) || (tc.expected != "" && got != tc.expected) {
				t.Fatalf("selected %q (via %q), want %q", got, sel.Via, tc.expected)
			}
		})
	}
}

func TestUDPOnlyDecoderInitializationRespectsSelection(t *testing.T) {
	previousConfig := decoderconfig.Instance
	previousQUIC, previousModbus, previousTLS := quic.Decoder.Writer, modbus.Decoder.Writer, tls.Decoder.Writer
	t.Cleanup(func() {
		decoderconfig.Instance = previousConfig
		quic.Decoder.Writer, modbus.Decoder.Writer, tls.Decoder.Writer = previousQUIC, previousModbus, previousTLS
	})
	for _, tc := range []struct {
		include string
		want    string
	}{
		{"Modbus", "Modbus"},
		{"QUICClientHello", "QUICClientHello"},
	} {
		t.Run(tc.include, func(t *testing.T) {
			cfg := decoderconfig.DefaultConfig.Clone()
			cfg.Out, cfg.IncludeDecoders, cfg.Null, cfg.Proto, cfg.Quiet = t.TempDir(), tc.include, true, false, true
			decoderconfig.Instance = cfg
			decoders, err := InitDecoders(cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range decoders {
				defer d.GetWriter().Close(0)
			}
			if len(decoders) != 1 || decoders[0].GetName() != tc.want {
				t.Fatalf("include %q initialized %v, want only %s", tc.include, decoders, tc.want)
			}
		})
	}
}

func TestSelectionUsesProductionTCPInputs(t *testing.T) {
	matchingEnv(t)
	dnp3 := matchingSample(t, "DNP3")
	modbus := matchingSample(t, "Modbus")
	for _, tc := range []struct {
		name, want, via string
		port            int32
		portClient      []byte
		scanClient      []byte
	}{
		{"complete frame on its port", "DNP3", ViaPort, dnp3.port, dnp3.client, dnp3.client},
		{"split header on its port", "DNP3", ViaFallback, dnp3.port, dnp3.client[:4], dnp3.client},
		{"split header on an alternate port", "DNP3", ViaFallback, 64999, dnp3.client[:4], dnp3.client},
		{"Modbus on DNP3 port", "Modbus", ViaFallback, dnp3.port, modbus.client, modbus.client},
		{"DNP3 on Modbus port", "DNP3", ViaFallback, modbus.port, dnp3.client, dnp3.client},
		{"incomplete frame", "", "", dnp3.port, dnp3.client[:4], dnp3.client[:4]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, ok := SelectDecoder(&SelectionInput{
				Transport: core.TCP, ServerPort: tc.port,
				PortClient: tc.portClient, ScanClient: tc.scanClient,
				Conversation: &core.ConversationInfo{},
			})
			if got := winner(sel, ok); (tc.want == "" && ok) || (tc.want != "" && got != tc.want) {
				t.Fatalf("decoder %q, wanted %q", got, tc.want)
			}
			if ok && sel.Via != tc.via {
				t.Errorf("selected via %q, wanted %q", sel.Via, tc.via)
			}
		})
	}
}

func TestWeakPortMatchDoesNotOverrideStrongerProtocolEvidence(t *testing.T) {
	matchingEnv(t)
	smtp := matchingSample(t, "SMTP")
	sel, ok := selectFor(smtp, core.TCP, 21)
	if !ok || sel.Name != "SMTP" || sel.Via != ViaFallback {
		t.Fatalf("SMTP banner on TCP/21 claimed by %+v (ok=%t), want SMTP over FTP's weaker 220 greeting", sel, ok)
	}
}

func TestTLSRecordOnlyStillUsesTLSStreamReader(t *testing.T) {
	matchingEnv(t)
	previousRecord, previousCertificate := tls.RecordDecoder.Writer, tls.Decoder.Writer
	t.Cleanup(func() {
		tls.RecordDecoder.Writer, tls.Decoder.Writer = previousRecord, previousCertificate
	})
	writer := &captureWriter{}
	tls.RecordDecoder.Writer, tls.Decoder.Writer = writer, nil
	decoderconfig.Instance.IncludeDecoders = "TLSRecord"
	data := []byte{23, 3, 3, 0, 2, 1, 2}
	client := core.DataFragments{hygieneFragment(data, 1_000_000_000, false)}
	sel, ok := SelectDecoder(&SelectionInput{
		Transport: core.TCP, ServerPort: 443,
		PortClient: data, ScanClient: data,
		Conversation: &core.ConversationInfo{
			Data: client, ClientData: client,
			ClientIP: "192.0.2.1", ServerIP: "192.0.2.2",
			ClientPort: 12345, ServerPort: 443,
		},
	})
	if !ok || sel.Name != "TLSCertificate" {
		t.Fatalf("TLSRecord-only selection yielded %+v (ok=%t), want the TLS stream reader", sel, ok)
	}
	sel.Decoder.Decode()
	if len(writer.records) != 1 {
		t.Fatalf("TLSRecord-only selection produced %v", writer.records)
	}
	if got := writer.records[0].(types.AuditRecord).NetcapType(); got != types.Type_NC_TLSRecord {
		t.Fatalf("TLSRecord-only selection produced %v", writer.records)
	}
}

func TestSelectionRespectsTransportAndStableTies(t *testing.T) {
	matchingEnv(t)
	for _, tc := range []struct {
		name        string
		sample      string
		transport   core.TransportProtocol
		port        int32
		want, route string
		winnerPort  int32
	}{
		{"TLS on TCP 443", "TLSCertificate", core.TCP, 443, "TLSCertificate", ViaPort, 443},
		{"QUIC on UDP 443", "QUICClientHello", core.UDP, 443, "QUICClientHello", ViaUDPList, 443},
		{"UDP protobuf on unregistered port", "Protobuf", core.UDP, 8127, "Protobuf", ViaFallback, 9090},
		{"TLS duplicated ports tie", "TLSCertificate", core.TCP, 64999, "TLSCertificate", ViaFallback, 443},
		{"CIP duplicated ports tie", "CIP", core.TCP, 64999, "CIP", ViaFallback, 2222},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := matchingSample(t, tc.sample)
			sel, ok := SelectDecoder(&SelectionInput{
				Transport: tc.transport, ServerPort: tc.port,
				PortClient: s.client, PortServer: s.server,
				ScanClient: s.client, ScanServer: s.server,
				Conversation: &core.ConversationInfo{},
			})
			if !ok || sel.Name != tc.want || sel.Via != tc.route || sel.Port != tc.winnerPort {
				t.Fatalf("selection %+v (ok=%t), want %s via %s on %d", sel, ok, tc.want, tc.route, tc.winnerPort)
			}
		})
	}
}

func TestUDPSelectionConsidersLaterCompleteDatagrams(t *testing.T) {
	matchingEnv(t)
	fixture := matchingSample(t, "BACnetIP")
	for _, tc := range []struct {
		name, via string
		port      int32
	}{
		{"registered port", ViaPort, fixture.port},
		{"unregistered port", ViaFallback, 64999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, ok := SelectDecoder(&SelectionInput{
				Transport: core.UDP, ServerPort: tc.port,
				PortClient: []byte{0}, ScanClient: []byte{0},
				Datagrams: []Datagram{
					{Client: true, Data: []byte{0}},
					{Client: true, Data: fixture.client},
				},
				Conversation: &core.ConversationInfo{},
			})
			if !ok || sel.Name != "BACnetIP" || sel.Via != tc.via {
				t.Fatalf("later BACnet datagram selected %+v (ok=%t), want BACnetIP via %s", sel, ok, tc.via)
			}
		})
	}
}

func TestUDPSelectionNeverJoinsSeparateDatagrams(t *testing.T) {
	matchingEnv(t)
	b := matchingSample(t, "BACnetIP").client
	sel, ok := SelectDecoder(&SelectionInput{
		Transport: core.UDP, ServerPort: 64999,
		PortClient: b[:2], ScanClient: b[:2],
		Datagrams: []Datagram{
			{Client: true, Data: b[:2]},
			{Client: true, Data: b[2:]},
		},
		Conversation: &core.ConversationInfo{},
	})
	if ok {
		t.Fatalf("two incomplete datagrams were concatenated into a false protocol match: %+v", sel)
	}
}

func TestAmbiguousUDPHeadersNeedTheirRegisteredPort(t *testing.T) {
	matchingEnv(t)
	s := matchingSample(t, "MQTTSN")
	for _, port := range []int32{1883, 1884} {
		sel, ok := selectFor(s, core.UDP, port)
		if !ok || sel.Name != "MQTTSN" || sel.Via != ViaPort {
			t.Errorf("MQTT-SN on registered port %d: %+v (ok=%t)", port, sel, ok)
		}
	}
	// 0x0e is also a gQUIC short-header-shaped byte. A complete MQTT-SN
	// datagram cannot establish either protocol off-port without more evidence.
	if sel, ok := selectFor(s, core.UDP, 64999); ok {
		t.Fatalf("MQTT-SN on an unknown port was guessed as %+v", sel)
	}
}

// The signature table is not sufficient evidence for the reader. Feed the
// complete fixture for each decoder to the production selector on its own and
// on an alternate port, then require the selected reader to be the one that
// the record-emission test actually drives.
func TestParseableReaderFixturesReachTheirDecoder(t *testing.T) {
	matchingEnv(t)
	for _, s := range samples() {
		t.Run(s.decoder, func(t *testing.T) {
			client, server := readerFixture(t, s)
			for _, port := range []int32{s.port, 64999} {
				in := &SelectionInput{
					Transport: s.transport, ServerPort: port,
					PortClient: client, PortServer: server,
					ScanClient: client, ScanServer: server,
					Conversation: &core.ConversationInfo{},
				}
				if s.transport == core.UDP {
					in.Datagrams = []Datagram{{Data: client, Client: true}}
					if len(server) > 0 {
						in.Datagrams = append(in.Datagrams, Datagram{Data: server})
					}
				}
				sel, ok := SelectDecoder(in)
				want := s.decoder
				if port != s.port && s.portOnly {
					want = "-"
				}
				if port != s.port && knownOffPortShadowing[s.decoder] != "" {
					want = knownOffPortShadowing[s.decoder]
				}
				if (want == "-" && ok) || (want != "-" && (!ok || sel.Name != want)) {
					t.Errorf("port %d: complete %s reader fixture went to %s (ok=%t), want %s", port, s.decoder, sel.Name, ok, want)
				}
			}
		})
	}
}
