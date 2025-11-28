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
	"testing"
)

func TestIPToInt64(t *testing.T) {
	if ipToInt64("127.0.0.1") != 2130706433 {
		t.Fatal("unexpected result")
	}
	if ipToInt64("127.0.0.2") != 2130706434 {
		t.Fatal("unexpected result")
	}

	if ipToInt64("2001:db8:85a3:8d3:1319:8a2e:370:7348") != 1376283091369227080 {
		t.Fatal("unexpected result")
	}

	// TODO: this way, half of the address is ignored...
	if ipToInt64("2001:db8:85a3:8d3:1319:8a2e:370:7348") == ipToInt64("ffff:ffff:ffff:ffff:1319:8a2e:370:7348") {
		t.Fatal("TODO: come up with a better way for a numeric representation of IPv6 addrs")
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
