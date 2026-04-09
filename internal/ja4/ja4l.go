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

package ja4

import "fmt"

// JA4L (TLS Latency) measures network latency by analyzing timing of initial packets.
// Licensed under FoxIO License 1.1.
//
// JA4L-C (Client Latency): Time from SYN to SYN-ACK (TCP RTT / 2)
// JA4L-S (Server Latency): Time from ClientHello to ServerHello
//
// Format: {latency_ms}_{ttl}
//
// Reference: https://github.com/FoxIO-LLC/ja4

// ComputeJA4L computes the JA4L latency fingerprint.
// Format: {latency_ms}_{ttl}
//
// Parameters:
//   - latencyNanos: Latency in nanoseconds (SYN→SYN-ACK for JA4L-C, ClientHello→ServerHello for JA4L-S)
//   - ttl: TTL value from the packet (used to estimate hop count/distance)
//
// Returns empty string if latency is not available (≤0).
func ComputeJA4L(latencyNanos int64, ttl uint8) string {
	if latencyNanos <= 0 {
		return ""
	}
	// Convert nanoseconds to milliseconds
	latencyMs := latencyNanos / 1_000_000
	return fmt.Sprintf("%d_%d", latencyMs, ttl)
}

// ComputeJA4LMicro computes the JA4L latency fingerprint with microsecond precision.
// Format: {latency_us}_{ttl}
//
// This variant provides higher precision for low-latency networks.
func ComputeJA4LMicro(latencyNanos int64, ttl uint8) string {
	if latencyNanos <= 0 {
		return ""
	}
	// Convert nanoseconds to microseconds
	latencyUs := latencyNanos / 1_000
	return fmt.Sprintf("%d_%d", latencyUs, ttl)
}

