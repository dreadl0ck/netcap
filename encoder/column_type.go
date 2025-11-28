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

package encoder

// ColumnType is the data type of the column
type ColumnType int

const (
	// TypeString is a data type for text columns
	TypeString ColumnType = iota

	// TypeNumeric is a data type for numeric columns
	TypeNumeric
)

func (c ColumnType) String() string {
	switch c {
	case TypeNumeric:
		return "numeric"
	case TypeString:
		return "string"
	default:
		return "invalid"
	}
}
