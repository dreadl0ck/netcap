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
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsVXLAN = []string{
	"Timestamp",
	"ValidIDFlag",      //  bool
	"VNI",              //  uint32
	"GBPExtension",     //  bool
	"GBPDontLearn",     //  bool
	"GBPApplied",       //  bool
	"GBPGroupPolicyID", //  int32
	"SrcIP",
	"DstIP",
}

func (a VXLAN) CSVHeader() []string {
	return filter(fieldsVXLAN)
}

func (a VXLAN) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.ValidIDFlag),  //  bool
		formatUint32(a.VNI),                //  uint32
		strconv.FormatBool(a.GBPExtension), //  bool
		strconv.FormatBool(a.GBPDontLearn), //  bool
		strconv.FormatBool(a.GBPApplied),   //  bool
		formatInt32(a.GBPGroupPolicyID),    //  int32
		a.Context.SrcIP,
		a.Context.DstIP,
	})
}

func (a VXLAN) Time() string {
	return a.Timestamp
}

func (a VXLAN) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var vxlanMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_VXLAN.String()),
		Help: Type_NC_VXLAN.String() + " audit records",
	},
	fieldsVXLAN[1:],
)

func init() {
	prometheus.MustRegister(vxlanMetric)
}

func (a VXLAN) Inc() {
	vxlanMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *VXLAN) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a VXLAN) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a VXLAN) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
