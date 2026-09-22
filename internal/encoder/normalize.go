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

	"gonum.org/v1/gonum/stat"
)

// float precision
const precision = 10

// MinMax will apply the minmax encoding.
func MinMax(value float64, sum *ColumnSummary) (result string) {

	sum.Lock()
	if value > sum.Max {
		sum.Max = value
	}
	if value < sum.Min {
		sum.Min = value
	}

	if sum.Min == sum.Max {
		result = strconv.FormatFloat(0, 'f', precision, 64)
	} else {
		result = strconv.FormatFloat((value-sum.Min)/(sum.Max-sum.Min), 'f', precision, 64)
	}

	sum.Unlock()
	return
}

// ZScore will apply the Zscore encoding.
func ZScore(value float64, sum *ColumnSummary) (result string) {

	sum.Lock()

	// TODO: use weights?
	sum.Mean, sum.Std = stat.MeanStdDev([]float64{sum.Mean, value}, nil)

	if sum.Std == 0 {
		result = strconv.FormatFloat(0, 'f', precision, 64)
	} else {
		if sum.Mean == value || sum.Mean == sum.Std {
			result = strconv.FormatFloat(value, 'f', precision, 64)
		} else {
			result = strconv.FormatFloat((value-sum.Mean)/sum.Std, 'f', precision, 64)
		}
	}

	sum.Unlock()

	return
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
