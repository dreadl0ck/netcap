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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsDot1Q = []string{
	"Timestamp",
	"Priority",       //  int32
	"DropEligible",   //  bool
	"VLANIdentifier", //  int32
	"Type",           //  int32
}

func (d *Dot1Q) CSVHeader() []string {
	return filter(fieldsDot1Q)
}

func (d *Dot1Q) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(d.Timestamp),
		formatInt32(d.Priority),            //  int32
		strconv.FormatBool(d.DropEligible), //  bool
		formatInt32(d.VLANIdentifier),      //  int32
		formatInt32(d.Type),                //  int32
	})
}

func (d *Dot1Q) Time() string {
	return d.Timestamp
}

func (d *Dot1Q) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(d)
}

var dot1qMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Dot1Q.String()),
		Help: Type_NC_Dot1Q.String() + " audit records",
	},
	fieldsDot1Q[1:],
)

func init() {
	prometheus.MustRegister(dot1qMetric)
}

func (d *Dot1Q) Inc() {
	dot1qMetric.WithLabelValues(d.CSVRecord()[1:]...).Inc()
}

func (d *Dot1Q) SetPacketContext(ctx *PacketContext) {}

// TODO: return Mac addr
func (d *Dot1Q) Src() string {
	return ""
}

func (d *Dot1Q) Dst() string {
	return ""
}
