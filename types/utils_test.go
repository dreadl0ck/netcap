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

package types

import (
	"math/big"
	"net"
	"testing"
)

func TestIPToInt64(t *testing.T) {
	// Test IPv4 addresses
	if ipToInt64("127.0.0.1") != 2130706433 {
		t.Fatal("unexpected result for 127.0.0.1")
	}
	if ipToInt64("127.0.0.2") != 2130706434 {
		t.Fatal("unexpected result for 127.0.0.2")
	}

	// Test that different IPv4 addresses produce different values
	if ipToInt64("192.168.1.1") == ipToInt64("192.168.1.2") {
		t.Fatal("different IPv4 addresses should produce different values")
	}

	// Test IPv6 addresses - should produce consistent hash values
	ipv6Result := ipToInt64("2001:db8:85a3:8d3:1319:8a2e:370:7348")
	if ipv6Result == 0 {
		t.Fatal("IPv6 address should not produce zero value")
	}

	// Test that the same IPv6 address produces consistent values
	if ipToInt64("2001:db8:85a3:8d3:1319:8a2e:370:7348") != ipv6Result {
		t.Fatal("same IPv6 address should produce consistent value")
	}

	// Test that IPv6 addresses with same lower 64 bits but different upper 64 bits
	// now produce DIFFERENT values (this was the bug - previously they would collide)
	addr1 := "2001:db8:85a3:8d3:1319:8a2e:370:7348"
	addr2 := "3001:db8:85a3:8d3:1319:8a2e:370:7348" // Different upper 64 bits, same lower 64 bits
	if ipToInt64(addr1) == ipToInt64(addr2) {
		t.Fatalf("IPv6 addresses with different upper 64 bits should produce different values: %s vs %s", addr1, addr2)
	}

	// Test more collision scenarios that previously would have failed
	addr3 := "::1"
	addr4 := "fe80::1" // Same lower bits as ::1
	if ipToInt64(addr3) == ipToInt64(addr4) {
		t.Fatalf("IPv6 addresses should not collide: %s vs %s", addr3, addr4)
	}

	// Test nil/invalid address handling
	if ipToInt64("invalid") != 0 {
		t.Fatal("invalid address should return 0")
	}
	if ipToInt64("") != 0 {
		t.Fatal("empty address should return 0")
	}
}

func TestMacToUint64(t *testing.T) {
	if macToUint64("02:f5:53:d3:82:70") != 4626045091369414704 {
		t.Fatal("unexpected result", macToUint64("02:f5:53:d3:82:70"))
	}
	if macToUint64("02:f5:53:d3:82:71") != 4626045091369414705 {
		t.Fatal("unexpected result", macToUint64("02:f5:53:d3:82:71"))
	}
}

// ipToInt64Old is the old implementation that used big.Int for both IPv4 and IPv6.
// For IPv6, this only used the lower 64 bits, causing collisions.
func ipToInt64Old(addr string) int64 {
	ip := net.ParseIP(addr)

	n := big.NewInt(0)
	if ip.To4() != nil {
		n.SetBytes(ip.To4())
	} else {
		n.SetBytes(ip.To16())
	}

	return n.Int64()
}

// Benchmarks for IPv4 addresses

func BenchmarkIPToInt64_IPv4_New(b *testing.B) {
	addr := "192.168.1.1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToInt64(addr)
	}
}

func BenchmarkIPToInt64_IPv4_Old(b *testing.B) {
	addr := "192.168.1.1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToInt64Old(addr)
	}
}

// Benchmarks for IPv6 addresses

func BenchmarkIPToInt64_IPv6_New(b *testing.B) {
	addr := "2001:db8:85a3:8d3:1319:8a2e:370:7348"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToInt64(addr)
	}
}

func BenchmarkIPToInt64_IPv6_Old(b *testing.B) {
	addr := "2001:db8:85a3:8d3:1319:8a2e:370:7348"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToInt64Old(addr)
	}
}

// Benchmarks for loopback addresses

func BenchmarkIPToInt64_Loopback4_New(b *testing.B) {
	addr := "127.0.0.1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToInt64(addr)
	}
}

func BenchmarkIPToInt64_Loopback6_New(b *testing.B) {
	addr := "::1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ipToInt64(addr)
	}
}
