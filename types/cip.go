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

package types

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsCIP = []string{
	"Timestamp",
	"Response",         // bool
	"ServiceID",        // int32
	"ClassID",          // uint32
	"InstanceID",       // uint32
	"Status",           // int32
	"AdditionalStatus", // []uint32
	"Data",             // []byte
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (c *CIP) CSVHeader() []string {
	return filter(fieldsCIP)
}

func (c *CIP) CSVRecord() []string {
	var additional = make([]string, len(c.AdditionalStatus))
	if c.Response {
		for _, v := range c.AdditionalStatus {
			additional = append(additional, formatUint32(v))
		}
	}
	// prevent accessing nil pointer
	if c.Context == nil {
		c.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(c.Timestamp),
		strconv.FormatBool(c.Response), // bool
		formatInt32(c.ServiceID),       // int32
		formatUint32(c.ClassID),        // uint32
		formatUint32(c.InstanceID),     // uint32
		formatInt32(c.Status),          // int32
		strings.Join(additional, ""),   // []uint32
		hex.EncodeToString(c.Data),     // []byte
		c.Context.SrcIP,
		c.Context.DstIP,
		c.Context.SrcPort,
		c.Context.DstPort,
	})
}

func (c *CIP) Time() string {
	return c.Timestamp
}

func (c *CIP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(c)
}

var cipMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CIP.String()),
		Help: Type_NC_CIP.String() + " audit records",
	},
	fieldsCIP[1:],
)

func init() {
	prometheus.MustRegister(cipMetric)
}

func (c *CIP) Inc() {
	cipMetric.WithLabelValues(c.CSVRecord()[1:]...).Inc()
}

func (c *CIP) SetPacketContext(ctx *PacketContext) {
	c.Context = ctx
}

func (c *CIP) Src() string {
	if c.Context != nil {
		return c.Context.SrcIP
	}
	return ""
}

func (c *CIP) Dst() string {
	if c.Context != nil {
		return c.Context.DstIP
	}
	return ""
}
