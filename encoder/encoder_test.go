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
	"fmt"
	"github.com/magiconair/properties/assert"
	"strconv"
	"testing"
)

var timestamps = []int64{
	1519915922831376000,
	1519932738687905000,
	1519932610143268000,
	1519915409848652000,
	1519929174958770000,
	1519914239743558000,
	1519914305588947000,
	1519913538020839000,
	1519928793139686000,
}

func TestEncodeTimeAsFloat(t *testing.T) {
	// TODO: add support for using this format for timestamps
	for _, r := range timestamps {
		fmt.Println(r, "==>", strconv.FormatFloat(float64(r)/float64(10000000000000000000), 'f', 16, 64))
	}
}

var numericTest = []int{5, 2, 6, 5, 2, 6}

func TestNumericZscoreEncoder(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		ZScore: true,
	}

	var res []string
	for _, val := range numericTest {
		res = append(res, encoder.Int("bytes", val))
	}

	assert.Equal(t, res, []string{"0.7071067812", "-0.7071067812", "0.7071067812", "0.7071067812", "-0.7071067812", "0.7071067812"}, "unexpected output")
}

func TestNumericMinMaxEncoder(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		MinMax: true,
	}

	var res []string
	for _, val := range numericTest {
		res = append(res, encoder.Int("bytes", val))
	}

	assert.Equal(t, res, []string{"0.0000000000", "0.0000000000", "1.0000000000", "0.7500000000", "0.0000000000", "1.0000000000"}, "unexpected output")
}

var categoricalTest = []string{
	"TCP",
	"UDP",
	"IPv4",
	"IPv6",
	"TCP",
	"UDP",
	"IPv4",
	"IPv6",
}

func TestCategoricalEncoder(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		NormalizeCategoricals: false,
	}

	var res []string
	for _, val := range categoricalTest {
		res = append(res, encoder.String("proto", val))
	}

	assert.Equal(t, res, []string{"0.0000000000", "1.0000000000", "2.0000000000", "3.0000000000", "0.0000000000", "1.0000000000", "2.0000000000", "3.0000000000"}, "expect incrementing ids for elements")
}

func TestZscoreNormalizedCategoricalEncoder(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		ZScore:                true,
		NormalizeCategoricals: true,
	}

	var res []string
	for _, val := range categoricalTest {
		res = append(res, encoder.String("proto", val))
	}

	assert.Equal(t, res, []string{"0.0000000000", "0.7071067812", "0.7071067812", "0.7071067812", "-0.7071067812", "-0.7071067812", "0.7071067812", "0.7071067812"}, "unexpected output")
}

func TestMinMaxNormalizedCategoricalEncoder(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		MinMax:                true,
		NormalizeCategoricals: true,
	}

	var res []string
	for _, val := range categoricalTest {
		res = append(res, encoder.String("proto", val))
	}

	assert.Equal(t, res, []string{"0.0000000000", "1.0000000000", "1.0000000000", "1.0000000000", "0.0000000000", "0.3333333333", "0.6666666667", "1.0000000000"}, "unexpected output")
}
