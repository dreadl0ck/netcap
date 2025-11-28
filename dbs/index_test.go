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

package dbs

import (
	"testing"
)

func TestIntermediatePatchVersions(t *testing.T) {
	versions := []string{"4.5.7", "4.5.8", "4.5.9", "4.5.10", "4.5.11"}
	generated := intermediatePatchVersions("4.5.6", "4.5.12")

	for i := 0; i < len(versions); i++ {
		if versions[i] != generated[i] {
			t.Fatal("expected ", versions[i], ", got ", generated[i])
		}
	}
}

func TestYearRange(t *testing.T) {
	y := yearRange(2017, 2020)
	expected := []string{"2017", "2018", "2019", "2020"}

	for i, elem := range expected {
		if elem != y[i] {
			t.Fatal(elem, " != ", y[i])
		}
	}
}
