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

package collector

import (
	"fmt"
	"sort"
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

	var summary string
	for _, e := range errs {
		summary += fmt.Sprintf("[%d] %s\n", e.count, e.msg)
	}

	return summary
}
