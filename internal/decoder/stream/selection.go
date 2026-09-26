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
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/modbus"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tls"
)

// How a decoder came to be chosen.
const (
	// ViaModbusRTU is the explicit RTU-over-TCP endpoint allowlist, which
	// precedes every signature.
	ViaModbusRTU = "modbus-rtu"

	// ViaPort is the decoder registered for the server port.
	ViaPort = "port"

	// ViaFallback is the port-independent scan.
	ViaFallback = "fallback"

	// ViaUDPList is the UDPStreamDecoders pass, which exists for protocols
	// sharing a port with a TCP decoder. QUIC is reachable only here.
	ViaUDPList = "udp-list"
)

// SelectionInput describes one conversation to choose a decoder for.
//
// The port pass and the fallback pass take different bytes, and deliberately
// so: TCP concatenates a whole direction before the fallback scan, because a
// length-prefixed protocol cannot be recognized from its first fragment alone,
// while the port pass sees only that fragment. UDP passes the first datagram to
// both. Carrying them as separate fields makes that difference visible instead
// of leaving it implicit in two copies of this logic.
type SelectionInput struct {
	// Transport filters the registry. A decoder is considered when its own
	// transport matches, or when it declares core.All.
	Transport core.TransportProtocol

	// ServerPort is the port the server listens on: for TCP that is the
	// client's destination, not the server's.
	ServerPort int32

	// PortClient and PortServer are the bytes offered to the port pass.
	PortClient, PortServer []byte

	// ScanClient and ScanServer are the bytes offered to the fallback scan.
	ScanClient, ScanServer []byte
	// UDP datagrams are independent messages. If the first is incomplete or
	// unrecognized, a later complete one may still identify the conversation;
	// their bytes must never be concatenated as though this were TCP.
	Datagrams []Datagram

	// Conversation is handed to the winning decoder's factory.
	Conversation *core.ConversationInfo
}

type Datagram struct {
	Data   []byte
	Client bool
}

// Selection is the outcome of SelectDecoder.
type Selection struct {
	API     core.StreamDecoderAPI
	Decoder core.StreamDecoderInterface
	Name    string
	Port    int32
	Via     string
}

// SelectDecoder chooses the decoder for a conversation.
//
// This is the single implementation for both transports. It previously existed
// twice, in tcp_connection.go and udp_stream.go, and the copies had drifted:
// only one carried the Modbus RTU pre-pass, only one concatenated a direction
// before the fallback scan, and only one consulted UDPStreamDecoders. Reading
// either copy gave a wrong account of how a protocol gets claimed.
//
// Ordering is unchanged from those copies: explicit endpoint, then the
// registered port, then an ascending-port scan, then the UDP-only list. The
// scan picks the most specific match. A strong registered-port match stays on
// the fast path; weak port matches are compared against the full conversation.
func SelectDecoder(in *SelectionInput) (Selection, bool) {
	if sel, ok := selectModbusRTU(in); ok {
		return sel, true
	}

	if sel, ok := selectByPort(in); ok {
		portScore, _ := matchScore(sel.API, in, true)
		// A short banner can match several services. Keep the usual fast port
		// path for structural evidence; only compare weak port matches with
		// the full conversation before committing to one decoder.
		if portScore > core.SpecificityWeak {
			return sel, true
		}
		if other, matched := selectByScan(in); matched && other.Name != sel.Name {
			scanScore, _ := matchScore(other.API, in, false)
			if scanScore > portScore {
				return other, true
			}
		}
		return sel, true
	}

	return selectByScan(in)
}

// eligible reports whether a decoder can serve this transport and can produce a
// reader. Both guards are part of the contract at every selection site.
func eligible(sd core.StreamDecoderAPI, transport core.TransportProtocol) bool {
	if sd.Transport() != transport && sd.Transport() != core.All {
		return false
	}

	return sd.GetReaderFactory() != nil
}

// InitDecoders filters its writer list, but matching uses the global registry.
// Without the same filter here an excluded decoder can win and then write no
// records, hiding traffic that an enabled decoder could have handled.
func configuredDecoder(name string) bool {
	c := decoderconfig.Instance
	if c == nil {
		return true
	}
	// TLSRecord is an abstract writer fed by TLSCertificate's stream reader.
	// Selecting only TLSRecord deliberately leaves the certificate writer nil;
	// the stream reader must nevertheless remain eligible to frame records.
	if name == tls.Decoder.GetName() && tls.RecordDecoder.Writer != nil &&
		!decoderListed(c.ExcludeDecoders, tls.RecordDecoder.GetName()) &&
		(c.IncludeDecoders == "" || decoderListed(c.IncludeDecoders, tls.RecordDecoder.GetName())) {
		return true
	}
	if c.IncludeDecoders != "" && !decoderListed(c.IncludeDecoders, name) {
		return false
	}
	return !decoderListed(c.ExcludeDecoders, name)
}

func decoderListed(list, name string) bool {
	for _, item := range strings.Split(list, ",") {
		if item == name {
			return true
		}
	}
	return false
}

func matchScore(sd core.StreamDecoderAPI, in *SelectionInput, portPass bool) (int, bool) {
	if in.Transport == core.UDP && len(in.Datagrams) > 0 {
		best, matched := 0, false
		for _, datagram := range in.Datagrams {
			client, server := datagram.Data, []byte(nil)
			if !datagram.Client {
				client, server = nil, datagram.Data
			}
			if sd.CanDecodeStream(client, server) {
				score := sd.MatchSpecificity(client, server)
				if !matched || score > best {
					best = score
				}
				matched = true
			}
		}
		return best, matched
	}
	client, server := in.ScanClient, in.ScanServer
	if portPass {
		client, server = in.PortClient, in.PortServer
	}
	if !sd.CanDecodeStream(client, server) {
		return 0, false
	}
	return sd.MatchSpecificity(client, server), true
}

// selectModbusRTU applies the RTU-over-TCP endpoint allowlist.
//
// Explicit transport selection must precede MBAP and generic signatures, and it
// only claims the connection while the decoder is live: when Modbus is
// excluded, a configured RTU endpoint must still reach the other decoders.
func selectModbusRTU(in *SelectionInput) (Selection, bool) {
	if in.Transport != core.TCP || modbus.Decoder.Writer == nil || !configuredDecoder(modbus.Decoder.GetName()) {
		return Selection{}, false
	}

	if !modbus.IsRTUConversation(in.Conversation) {
		return Selection{}, false
	}

	return Selection{
		API:     modbus.Decoder,
		Decoder: modbus.Decoder.Factory.New(in.Conversation),
		Name:    modbus.Decoder.GetName(),
		Port:    in.ServerPort,
		Via:     ViaModbusRTU,
	}, true
}

// selectByPort tries the decoder registered for the server port. For UDP it
// checks independent datagrams without concatenating their payloads.
func selectByPort(in *SelectionInput) (Selection, bool) {
	sd, exists := DefaultStreamDecoders[in.ServerPort]
	if !exists || !eligible(sd, in.Transport) || !configuredDecoder(sd.GetName()) {
		return Selection{}, false
	}

	if _, ok := matchScore(sd, in, true); !ok {
		return Selection{}, false
	}

	return Selection{
		API:     sd,
		Decoder: sd.GetReaderFactory().New(in.Conversation),
		Name:    sd.GetName(),
		Port:    in.ServerPort,
		Via:     ViaPort,
	}, true
}

// selectByScan asks every eligible decoder and keeps the one that required the
// most evidence.
//
// It used to keep the first that said yes, walking ports in ascending order.
// Port number is not a measure of anything, so that let a one-byte check on a
// low port outrank a checksum on a high one: measured over one sample per
// decoder, 5 of 29 protocols went to the wrong decoder off their own port. The
// plainest case was SMTP, whose signature requires everything FTP's does and
// more, losing because 25 > 21.
//
// Ties keep ascending port order, which is what SortedDecoderPorts is for:
// ranging over the map let a different decoder win between runs whenever
// several matched equally.
func selectByScan(in *SelectionInput) (Selection, bool) {
	var (
		best  core.StreamDecoderAPI
		port  int32
		via   string
		score int
	)

	consider := func(sd core.StreamDecoderAPI, p int32, v string) {
		if sd == best || !eligible(sd, in.Transport) || !configuredDecoder(sd.GetName()) {
			return
		}
		if d, ok := sd.(*decoder.StreamDecoder); ok && d.PortOnly {
			return
		}

		s, ok := matchScore(sd, in, false)
		if !ok {
			return
		}
		if d, ok := sd.(*decoder.StreamDecoder); ok && s < d.FallbackMinSpecificity {
			return
		}

		if best == nil || s > score {
			best, port, via, score = sd, p, v, s
		}
	}

	for _, p := range SortedDecoderPorts {
		consider(DefaultStreamDecoders[p], p, ViaFallback)
	}

	// The UDP-only decoders compete here rather than in a pass of their own
	// after this one. They are absent from the port map because they share a
	// port with a TCP decoder, which says nothing about how good their
	// signature is -- and running them last meant QUIC, whose Initial packet
	// protobuf accepts, was never reached at all.
	for _, sd := range UDPStreamDecoders {
		consider(sd, in.ServerPort, ViaUDPList)
	}

	if best == nil {
		return Selection{}, false
	}

	return Selection{
		API:     best,
		Decoder: best.GetReaderFactory().New(in.Conversation),
		Name:    best.GetName(),
		Port:    port,
		Via:     via,
	}, true
}
