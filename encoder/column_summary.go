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

import "sync"

// ColumnSummary collects statistical information about a column in the dataset.
type ColumnSummary struct {
	Version string `json:"version"`
	Col     string `json:"col"`

	// Data type of the column, eg: string or numeric
	Typ ColumnType `json:"typ"`

	// Map of strings mapped to their index
	// tracked as float64 to avoid additional type casts
	UniqueStrings map[string]float64 `json:"uniqueStrings"`

	// Current string index
	// tracked as float64 to avoid additional type casts
	Index float64

	// standard deviation and mean
	Std  float64 `json:"std"`
	Mean float64 `json:"mean"`

	// min, max
	Min float64 `json:"min"`
	Max float64 `json:"max"`

	sync.Mutex
}
