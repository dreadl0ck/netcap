/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package types

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	Begin     = "("
	End       = ")"
	Separator = "-"
)

type Stringable interface {
	ToString() string
}

// panic: value method github.com/dreadl0ck/netcap/types.LSUpdate.ToString called using nil *LSUpdate pointer
// func toString(v Stringable) string {
// 	if v != nil {
// 		return v.ToString()
// 	}
// 	return ""
// }

// this function wraps the ToString() function call with a nil pointer check
func toString(c Stringable) string {

	// make sure its not a nil pointer
	// a simple nil check is apparently not enough here
	if c == nil || (reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()) {
		return ""
	}

	// now check if the Stringable interface is implemented
	if str, ok := c.(Stringable); ok {
		return str.ToString()
	}

	// in case the Stringable interface is not implemented: fail
	spew.Dump(c)
	panic("toString called with an instance that does not implement the Stringable interface")
}

func joinInts(a []int32) string {
	var (
		b         strings.Builder
		lastIndex = len(a) - 1
	)
	b.WriteString(Begin)
	for i, num := range a {
		b.WriteString(formatInt32(num))
		if i != lastIndex {
			b.WriteString(Separator)
		}
	}
	b.WriteString(End)
	return b.String()
}

func joinUints(a []uint32) string {
	var (
		b         strings.Builder
		lastIndex = len(a) - 1
	)
	b.WriteString(Begin)
	for i, num := range a {
		b.WriteString(formatUint32(num))
		if i != lastIndex {
			b.WriteString(Separator)
		}
	}
	b.WriteString(End)
	return b.String()
}

func join(a ...string) string {
	var (
		b         strings.Builder
		lastIndex = len(a) - 1
	)
	b.WriteString(Begin)
	for i, v := range a {
		b.WriteString(v)
		if i != lastIndex {
			b.WriteString(Separator)
		}
	}
	b.WriteString(End)
	return b.String()
}

func formatTimestamp(ts string) string {
	if UTC {
		return utils.TimeToUTC(ts)
	}
	return ts
}

func formatInt32(v int32) string {
	return strconv.FormatInt(int64(v), 10)
}

func formatInt64(v int64) string {
	return strconv.FormatInt(v, 10)
}

func formatUint32(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

func formatUint64(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func formatFloat64(v float64) string {
	return strconv.FormatFloat(v, 'f', 6, 64)
}
