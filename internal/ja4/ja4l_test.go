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

import "testing"

func TestComputeJA4L(t *testing.T) {
	tests := []struct {
		name         string
		latencyNanos int64
		ttl          uint8
		want         string
	}{
		{
			name:         "Zero latency returns empty",
			latencyNanos: 0,
			ttl:          64,
			want:         "",
		},
		{
			name:         "Negative latency returns empty",
			latencyNanos: -1000000,
			ttl:          64,
			want:         "",
		},
		{
			name:         "1ms latency with TTL 64",
			latencyNanos: 1_000_000,
			ttl:          64,
			want:         "1_64",
		},
		{
			name:         "10ms latency with TTL 128",
			latencyNanos: 10_000_000,
			ttl:          128,
			want:         "10_128",
		},
		{
			name:         "100ms latency with TTL 255",
			latencyNanos: 100_000_000,
			ttl:          255,
			want:         "100_255",
		},
		{
			name:         "Sub-millisecond latency (500us) rounds down to 0",
			latencyNanos: 500_000,
			ttl:          64,
			want:         "0_64",
		},
		{
			name:         "1.5ms latency rounds down to 1ms",
			latencyNanos: 1_500_000,
			ttl:          64,
			want:         "1_64",
		},
		{
			name:         "Zero TTL",
			latencyNanos: 50_000_000,
			ttl:          0,
			want:         "50_0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeJA4L(tt.latencyNanos, tt.ttl)
			if got != tt.want {
				t.Errorf("ComputeJA4L(%d, %d) = %q, want %q", tt.latencyNanos, tt.ttl, got, tt.want)
			}
		})
	}
}

func TestComputeJA4LMicro(t *testing.T) {
	tests := []struct {
		name         string
		latencyNanos int64
		ttl          uint8
		want         string
	}{
		{
			name:         "Zero latency returns empty",
			latencyNanos: 0,
			ttl:          64,
			want:         "",
		},
		{
			name:         "1ms latency = 1000us",
			latencyNanos: 1_000_000,
			ttl:          64,
			want:         "1000_64",
		},
		{
			name:         "500us latency",
			latencyNanos: 500_000,
			ttl:          128,
			want:         "500_128",
		},
		{
			name:         "10us latency",
			latencyNanos: 10_000,
			ttl:          64,
			want:         "10_64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeJA4LMicro(tt.latencyNanos, tt.ttl)
			if got != tt.want {
				t.Errorf("ComputeJA4LMicro(%d, %d) = %q, want %q", tt.latencyNanos, tt.ttl, got, tt.want)
			}
		})
	}
}

