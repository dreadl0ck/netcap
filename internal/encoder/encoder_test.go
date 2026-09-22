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

import (
	"strconv"
	"testing"

	"github.com/magiconair/properties/assert"
	"gonum.org/v1/gonum/stat"
)

var numericTestZero = []int{0, 0, 0, 0, 0, 0}

func TestNumericZscoreEncoderZero(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		ZScore: true,
	}

	var res []string
	for _, val := range numericTestZero {
		res = append(res, encoder.Int("bytes", val))
	}

	assert.Equal(t, res, []string{"0.0000000000", "0.0000000000", "0.0000000000", "0.0000000000", "0.0000000000", "0.0000000000"}, "unexpected output")
}

func TestNumericMinMaxEncoderZero(t *testing.T) {
	var encoder = NewValueEncoder()
	encoder.conf = &Config{
		MinMax: true,
	}

	var res []string
	for _, val := range numericTestZero {
		res = append(res, encoder.Int("bytes", val))
	}

	assert.Equal(t, res, []string{"0.0000000000", "0.0000000000", "0.0000000000", "0.0000000000", "0.0000000000", "0.0000000000"}, "unexpected output")
}

var numericTest = []int{5, 2, 6, 5, 2, 6}
var numericTestFloat = []float64{5, 2, 6, 5, 2, 6}

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

func TestZscoreAllData(t *testing.T) {

	// TODO: use weights?
	mean, std := stat.MeanStdDev(numericTestFloat, nil)

	var res []string
	for _, val := range numericTestFloat {
		res = append(res, strconv.FormatFloat((val-mean)/std, 'f', precision, 64))
	}

	assert.Equal(t, res, []string{"0.3580574370", "-1.2532010296", "0.8951435925", "0.3580574370", "-1.2532010296", "0.8951435925"}, "unexpected output")
}

func TestZscoreAllDataWeights(t *testing.T) {

	var numericTestFloatWeights = []float64{0.1, 0.5, 0.2, 0.1, 0.5, 0.2}

	// MeanVariance computes the sample mean and unbiased variance, where the mean and variance are
	//  \sum_i w_i * x_i / (sum_i w_i)
	//  \sum_i w_i (x_i - mean)^2 / (sum_i w_i - 1)
	// respectively.
	// If weights is nil then all of the weights are 1. If weights is not nil, then
	// len(x) must equal len(weights).
	// When weights sum to 1 or less, a biased variance estimator should be used.
	mean, std := stat.MeanStdDev(numericTestFloat, numericTestFloatWeights)

	var res []string
	for _, val := range numericTestFloat {
		res = append(res, strconv.FormatFloat((val-mean)/std, 'f', precision, 64))
	}

	assert.Equal(t, res, []string{"0.5533167450", "-0.4681910919", "0.8938193573", "0.5533167450", "-0.4681910919", "0.8938193573"}, "unexpected output")
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
