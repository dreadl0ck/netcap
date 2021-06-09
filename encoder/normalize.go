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
	"strconv"
)

// float precision
const precision = 10

// MinMax will apply the minmax encoding.
func MinMax(value float64, sum *ColumnSummary) string {

	// TODO: the first value (and all columns with a single identical value) will always yield NaN: use a static value?
	if sum.Min == sum.Max {
		return "1.0000000000"
	}

	return strconv.FormatFloat((value-sum.Min)/(sum.Max-sum.Min), 'f', precision, 64)
}

// ZScore will apply the Zscore encoding.
func ZScore(i float64, sum *ColumnSummary) string {

	// TODO: the first value (and all columns with a single identical value) will always yield NaN: use a static value?
	if sum.Mean == i {
		return "1.0000000000"
	}

	return strconv.FormatFloat((i-sum.Mean)/sum.Std, 'f', precision, 64)
}

// GetIndex returns the index for a value in a string array.
func GetIndex(arr []string, val string) float64 {

	for index, v := range arr {
		if v == val {
			return float64(index)
		}
	}

	return float64(0)
}

// MinMaxIntArr returns the highest and the lowest numbers from a float64 array.
func MinMaxIntArr(array []float64) (float64, float64) {
	var (
		max float64 = array[0]
		min float64 = array[0]
	)
	for _, value := range array {
		if max < value {
			max = value
		}
		if min > value {
			min = value
		}
	}
	return min, max
}
