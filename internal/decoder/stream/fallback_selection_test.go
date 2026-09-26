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
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

// fallbackWinner runs the production selector with a port no decoder is
// registered for, so the port pass cannot match and the fallback scan decides.
//
// This drives SelectDecoder rather than modelling it. An earlier version was a
// hand-copied loop, which is the shape of bug it exists to catch: a test that
// agrees with a model while production disagrees.
func fallbackWinner(client, server []byte) (name string, port int32) {
	sel, ok := SelectDecoder(&SelectionInput{
		Transport:    core.TCP,
		ServerPort:   unregisteredPort,
		PortClient:   client,
		PortServer:   server,
		ScanClient:   client,
		ScanServer:   server,
		Conversation: &core.ConversationInfo{},
	})
	if !ok {
		return "", 0
	}

	return sel.Name, sel.Port
}

// unregisteredPort is absent from DefaultStreamDecoders, so selection falls
// through to the scan.
const unregisteredPort = 64999

func repeat(frame []byte, n int) []byte {
	out := make([]byte, 0, len(frame)*n)
	for range n {
		out = append(out, frame...)
	}

	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// DNP3 carries the only real checksum validation in the estate and sits at port
// 20000, so the ascending scan asks it 29th of 33. Three decoders below it used
// to claim its traffic: kerberosaudit (88) on the outstation address byte,
// socks (1080) on the 0x05 start byte, and iec62351 (2404) on a loose scan for
// 0x78.
func TestDNP3SurvivesTheFallbackScan(t *testing.T) {
	// Real frames from tests/ICS-pcap/DNP3.
	for _, tt := range []struct {
		name  string
		frame string
	}{
		{"select", "05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b"},
		{"operate", "05641ac403000400c9b7c1c2040c01280100010003016400000083546400000000005b"},
		{"read", "05640bc403000400ef7ac1c1013c0206b576"},
		{"write", "056412c403000400152dc1c10232010701fa7d0b460d01c863"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stream := repeat(mustHex(t, tt.frame), 8)

			if name, port := fallbackWinner(stream, nil); name != "DNP3" {
				t.Errorf("client direction claimed by %q on port %d, want DNP3", name, port)
			}
			if name, port := fallbackWinner(nil, stream); name != "DNP3" {
				t.Errorf("server direction claimed by %q on port %d, want DNP3", name, port)
			}
		})
	}
}

// The specific byte that let kerberosaudit take a DNP3 conversation: byte 4 of
// the frame is the outstation's destination address low byte, and five values
// of it are Kerberos ASN.1 application tags.
func TestDNP3SurvivesEveryOutstationAddress(t *testing.T) {
	frame := mustHex(t, "05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b")

	for addr := range 256 {
		mutated := append([]byte(nil), frame...)
		mutated[4] = byte(addr)
		binary.LittleEndian.PutUint16(mutated[8:10], dnp3TestCRC(mutated[:8]))
		if !DefaultStreamDecoders[20000].CanDecodeStream(mutated, nil) {
			t.Fatalf("address %#02x: frame with recomputed CRC was rejected", addr)
		}

		if name, port := fallbackWinner(mutated, nil); name != "DNP3" {
			t.Fatalf("outstation address low byte %#02x: claimed by %q on port %d", addr, name, port)
		}
	}
}

func dnp3TestCRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// Modbus validates a complete ADU and parses it, but sits at 502 behind
// tacacs (49) and kerberosaudit (88), both of which key on the transaction id.
func TestModbusSurvivesEveryTransactionID(t *testing.T) {
	for hi := range 256 {
		// txid, protocol id 0, length 6, unit 1, FC3 read holding registers.
		adu := []byte{byte(hi), 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A}

		if name, port := fallbackWinner(adu, nil); name != "Modbus" {
			t.Errorf("transaction ID high byte %#02x: claimed by %q on port %d", hi, name, port)
		}
	}
}

// Documents which decoders still shadow others, so the residual risk is a
// measured list rather than an assumption. Not an assertion: tacacs and s7comm
// are known open defects, deliberately out of scope.
func TestFallbackShadowingIsRecorded(t *testing.T) {
	dnp3 := repeat(mustHex(t, "05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b"), 8)

	var claimants []string

	for _, p := range SortedDecoderPorts {
		sd := DefaultStreamDecoders[p]
		if sd.Transport() != core.TCP && sd.Transport() != core.All {
			continue
		}

		if sd.CanDecodeStream(dnp3, nil) {
			claimants = append(claimants, sd.GetName())
		}
	}

	t.Logf("decoders accepting a DNP3 stream: %v", claimants)

	if len(claimants) != 1 || claimants[0] != "DNP3" {
		t.Errorf("DNP3 traffic is accepted by %v; only DNP3 should accept it", claimants)
	}
}
