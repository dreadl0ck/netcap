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
	"sort"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tls"
)

// matchingEnv pins the state that changes what CanDecode answers.
//
// Two things do. tls.RecordDecoder.Writer swings TLS between accepting any
// 3-byte record header and requiring a full ClientHello, and TLS sits at port
// 443 in the middle of the scan. decoderconfig.Instance is read by the Modbus
// RTU pre-pass, which nil-dereferences without it.
//
// Without both pinned the matrix measures whatever the test binary happened to
// initialise, which is not a property of the decoders.
func matchingEnv(t *testing.T) {
	t.Helper()

	config, writer := decoderconfig.Instance, tls.RecordDecoder.Writer
	t.Cleanup(func() {
		decoderconfig.Instance, tls.RecordDecoder.Writer = config, writer
	})

	decoderconfig.Instance = &decoderconfig.Config{}
	tls.RecordDecoder.Writer = nil
}

// selectFor runs the production selector for one sample over one transport.
// port is the server port to present the conversation on.
func selectFor(s sample, transport core.TransportProtocol, port int32) (Selection, bool) {
	return SelectDecoder(&SelectionInput{
		Transport:    transport,
		ServerPort:   port,
		PortClient:   s.client,
		PortServer:   s.server,
		ScanClient:   s.client,
		ScanServer:   s.server,
		Conversation: &core.ConversationInfo{},
	})
}

func winner(sel Selection, ok bool) string {
	if !ok {
		return "-"
	}

	return sel.Name
}

// registeredDecoders returns every decoder name in either registry.
func registeredDecoders() []string {
	seen := map[string]bool{}

	for _, sd := range DefaultStreamDecoders {
		seen[sd.GetName()] = true
	}

	for _, sd := range UDPStreamDecoders {
		seen[sd.GetName()] = true
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// A decoder with no sample is a hole in the matrix, not a pass.
func TestEveryDecoderHasASample(t *testing.T) {
	covered := map[string]bool{}
	for _, s := range samples() {
		covered[s.decoder] = true
	}

	var missing []string

	for _, name := range registeredDecoders() {
		if !covered[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Errorf("no traffic sample for %d decoder(s): %v", len(missing), missing)
	}

	t.Logf("%d decoders registered, %d samples", len(registeredDecoders()), len(samples()))
}

// The diagonal, on the port pass. A sample presented on its own port should
// reach its own decoder.
//
// This is the weakest of the three assertions: samples are largely built from
// the signatures they are tested against, so a green diagonal shows the sample
// is well formed rather than that the decoder is correct. The off-diagonal is
// where the information is.
func TestSampleReachesItsOwnDecoderOnItsPort(t *testing.T) {
	matchingEnv(t)

	for _, s := range samples() {
		t.Run(s.decoder, func(t *testing.T) {
			sel, ok := selectFor(s, s.transport, s.port)

			if s.takenOnPort != "" {
				if got := winner(sel, ok); got != s.takenOnPort {
					t.Errorf("port %d: claimed by %q; recorded as taken by %q", s.port, got, s.takenOnPort)
				}

				return
			}

			if got := winner(sel, ok); got != s.decoder {
				t.Errorf("port %d: claimed by %q, want %q", s.port, got, s.decoder)

				return
			}

			want := s.wantVia
			if want == "" {
				want = ViaPort
			}

			if sel.Via != want {
				t.Errorf("port %d: reached via %q, want %q", s.port, sel.Via, want)
			}
		})
	}
}

// The census: every decoder that accepts each sample, regardless of ordering.
//
// This is the fact base. A protocol with more than one claimant is reachable on
// its own port only by luck of registration, and off its own port only if the
// competing claimants all sit above it.
func TestDecoderMatchingCensus(t *testing.T) {
	matchingEnv(t)

	var rows []string

	conflicts := 0

	for _, s := range samples() {
		var claimants []string

		for _, port := range SortedDecoderPorts {
			sd := DefaultStreamDecoders[port]
			if !eligible(sd, s.transport) {
				continue
			}

			if sd.CanDecodeStream(s.client, s.server) {
				claimants = append(claimants, fmt.Sprintf("%s(%d)", sd.GetName(), port))
			}
		}

		for _, sd := range UDPStreamDecoders {
			if eligible(sd, s.transport) && sd.CanDecodeStream(s.client, s.server) {
				claimants = append(claimants, sd.GetName()+"(udp-list)")
			}
		}

		others := 0

		for _, c := range claimants {
			if !strings.HasPrefix(c, s.decoder+"(") {
				others++
			}
		}

		if others > 0 {
			conflicts++
		}

		rows = append(rows, fmt.Sprintf("%-16s %d other claimant(s): %s", s.decoder, others, strings.Join(claimants, " ")))
	}

	t.Log("decoders accepting each sample:\n" + strings.Join(rows, "\n"))
	t.Logf("%d of %d samples are accepted by more than their own decoder", conflicts, len(samples()))
}

// The matrix: what wins on each selection path.
//
// unregisteredPort forces the fallback scan, which is how a protocol on a
// nonstandard port is classified. Where that column disagrees with the decoder
// column, the protocol is unreachable off its own port.
func TestDecoderMatchingMatrix(t *testing.T) {
	matchingEnv(t)

	var (
		rows     []string
		shadowed []string
	)

	rows = append(rows, fmt.Sprintf("%-16s %-6s %-16s %-16s %s", "SAMPLE", "PORT", "ON-PORT", "OFF-PORT", "VERDICT"))

	for _, s := range samples() {
		onPort := winner(selectFor(s, s.transport, s.port))
		offPort := winner(selectFor(s, s.transport, unregisteredPort))

		verdict := "ok"

		switch {
		case onPort != s.decoder && offPort != s.decoder:
			verdict = "UNREACHABLE"
		case onPort != s.decoder:
			verdict = "on-port taken by " + onPort
		case offPort != s.decoder:
			verdict = "SHADOWED off-port by " + offPort
		}

		if verdict != "ok" {
			shadowed = append(shadowed, fmt.Sprintf("%s: %s", s.decoder, verdict))
		}

		rows = append(rows, fmt.Sprintf("%-16s %-6d %-16s %-16s %s", s.decoder, s.port, onPort, offPort, verdict))
	}

	t.Log("decoder selection matrix:\n" + strings.Join(rows, "\n"))

	if len(shadowed) > 0 {
		t.Logf("%d of %d samples do not reach their own decoder on every path:\n  %s",
			len(shadowed), len(samples()), strings.Join(shadowed, "\n  "))
	}
}

// Pins the shadowing that is currently accepted, so the matrix is a diff rather
// than a wall of failures, and so closing one shows up as a change here.
//
// Every entry is a defect. They are recorded rather than asserted-against
// because fixing them is a separate change; see
// docs/industrial-control-systems.md.
var knownOffPortShadowing = map[string]string{
	// FTP tests server[0:3] == "220"; an SMTP greeting opens "220 " too. SMTP's
	// own check is strictly stronger -- it also requires "SMTP" in the banner --
	// and loses only because 25 > 21. The clearest case of ordering, not
	// signature, deciding.
	"SMTP": "FTP",

	// A SOCKS5 greeting is 05 01 00, which satisfies DCE/RPC's version 5,
	// minor 0 or 1, packet type <= 19.
	"SOCKS": "DCERPC",

	// s7comm accepts any non-DT COTP PDU type without checking for an S7
	// payload, so every X.224 connection request is claimed at port 102.
	"RDP": "S7Comm",

	// CIP's ENIP check accepts a DCE/RPC header.
	"PROFINET": "CIP",

	// Not shadowing in the same sense: QUIC is in no port map, and protobuf
	// accepts a QUIC Initial before the UDP list pass is reached.
	"QUICClientHello": "Protobuf",
}

func TestKnownShadowingIsUnchanged(t *testing.T) {
	matchingEnv(t)

	actual := map[string]string{}

	for _, s := range samples() {
		if got := winner(selectFor(s, s.transport, unregisteredPort)); got != s.decoder {
			actual[s.decoder] = got
		}
	}

	for decoder, thief := range actual {
		if want, ok := knownOffPortShadowing[decoder]; !ok {
			t.Errorf("new off-port shadowing: %s taken by %s", decoder, thief)
		} else if want != thief {
			t.Errorf("%s is now taken by %s, was %s", decoder, thief, want)
		}
	}

	for decoder, thief := range knownOffPortShadowing {
		if _, ok := actual[decoder]; !ok {
			t.Errorf("%s is no longer shadowed by %s; remove it from knownOffPortShadowing", decoder, thief)
		}
	}
}
