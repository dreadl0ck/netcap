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

import (
	"log"
	"math"
	"strconv"
	"sync"

	"github.com/davecgh/go-spew/spew"
)

// ValueEncoder handles online encoding of incoming data and keeps the required state for each feature.
type ValueEncoder struct {

	// columnSummaries
	columns map[string]*ColumnSummary

	// configuration
	conf *Config

	sync.Mutex
}

// array of all registered encoders
var encoders []*ValueEncoder

// LoadValueEncoders loads all value encoders from disk.
func LoadValueEncoders() {
	// TODO:
}

// StoreValueEncoders stores all value encoders on disk.
func StoreValueEncoders() {
	// TODO:
}

// SetConfig will set the config for all registered encoders.
func SetConfig(c *Config) {
	for _, m := range encoders {
		m.conf = c
	}
}

// NewValueEncoder returns a new encoding manager instance.
func NewValueEncoder() *ValueEncoder {

	man := &ValueEncoder{
		columns: map[string]*ColumnSummary{},
	}

	encoders = append(encoders, man)

	return man
}

// Config holds configuration parameters.
type Config struct {

	// use zscore for normalization
	ZScore bool

	// use minmax for normalization
	MinMax bool

	// normalize the categorical values after encoding them to numeric format
	NormalizeCategoricals bool
}

// String handles encoding of categorical values according to the ValueEncoder configuration.
func (m *ValueEncoder) String(field string, val string) string {

	sum := m.GetSummary(TypeString, field)

	m.Lock()
	i, ok := sum.UniqueStrings[val]
	if !ok {
		sum.UniqueStrings[val] = sum.Index
		i = sum.Index
		sum.Index++
	}
	m.Unlock()

	if m.conf.NormalizeCategoricals {
		if m.conf.ZScore {
			return ZScore(i, sum)
		}

		if m.conf.MinMax {
			return MinMax(i, sum)
		}
	}

	return strconv.FormatFloat(i, 'f', precision, 64)
}

// Int handles encoding of integer values according to the ValueEncoder configuration.
func (m *ValueEncoder) Int(field string, val int) string {
	return m.Float64(field, float64(val))
}

// Int64 handles encoding of 64bit integer values according to the ValueEncoder configuration.
func (m *ValueEncoder) Int64(field string, val int64) string {
	return m.Float64(field, float64(val))
}

// Int32 handles encoding of 32bit integer values according to the ValueEncoder configuration.
func (m *ValueEncoder) Int32(field string, val int32) string {
	return m.Float64(field, float64(val))
}

// Uint32 handles encoding of unsigned 32bit integer values according to the ValueEncoder configuration.
func (m *ValueEncoder) Uint32(field string, val uint32) string {
	return m.Float64(field, float64(val))
}

// Uint64 handles encoding of unsigned 64bit integer values according to the ValueEncoder configuration.
func (m *ValueEncoder) Uint64(field string, val uint64) string {
	return m.Float64(field, float64(val))
}

const (
	valueTrue  = "1.0000000000"
	valueFalse = "0.0000000000"
)

// Bool handles encoding of boolean values to numeric format.
func (m *ValueEncoder) Bool(b bool) string {
	if b {
		return valueTrue
	}
	return valueFalse
}

// Float64 handles encoding of 64bit float values according to the ValueEncoder configuration.
func (m *ValueEncoder) Float64(field string, val float64) string {

	var (
		result string
		sum    = m.GetSummary(TypeNumeric, field)
	)

	switch {
	case m.conf.ZScore:
		result = ZScore(val, sum)
	case m.conf.MinMax:
		result = MinMax(val, sum)
	default:
		spew.Dump(m.conf)
		log.Fatal("invalid config: no normalization strategy")
	}

	return result
}

// GetSummary returns the summary for the given column type and field name.
// It will create a new one if none is being tracked yet.
func (m *ValueEncoder) GetSummary(colType ColumnType, field string) *ColumnSummary {

	// get column summary for current field
	m.Lock()
	sum, ok := m.columns[field]
	if !ok {
		sum = &ColumnSummary{
			Col:           field,
			Typ:           colType,
			UniqueStrings: map[string]float64{},
			Min:           math.MaxFloat64,
		}
		m.columns[field] = sum
	}
	m.Unlock()

	return sum
}
