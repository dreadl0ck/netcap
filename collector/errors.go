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

package collector

import (
	"fmt"
	"sort"
	"strings"
)

type decodingError struct {
	msg   string
	count int64
}

// decodingErrorSlice implements sort.Interface to sort decodingErrors based on their number of occurrence.
type decodingErrorSlice []decodingError

// Len will return the length.
func (d decodingErrorSlice) Len() int {
	return len(d)
}

// Less will return true if the value at index i is smaller than the other one.
func (d decodingErrorSlice) Less(i, j int) bool {
	return d[i].count < d[j].count
}

// Swap will switch the values.
func (d decodingErrorSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (c *Collector) getErrorSummary() string {
	c.errorMap.Lock()

	var errs decodingErrorSlice
	for msg, count := range c.errorMap.Items {
		errs = append(errs, decodingError{
			msg:   msg,
			count: count,
		})
	}

	c.errorMap.Unlock()

	sort.Sort(errs)

	var summary strings.Builder
	for _, e := range errs {
		summary.WriteString(fmt.Sprintf("[%d] %s\n", e.count, e.msg))
	}

	return summary.String()
}
