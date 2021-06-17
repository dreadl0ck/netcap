/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
