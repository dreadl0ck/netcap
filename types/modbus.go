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
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsModbus = []string{
	"Timestamp",
	"TransactionID", // int32
	"ProtocolID",    // int32
	"Length",        // int32
	"UnitID",        // int32
	"Payload",       // []byte
	"Exception",     // bool
	"FunctionCode",  // int32
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (a Modbus) CSVHeader() []string {
	return filter(fieldsModbus)
}

func (a Modbus) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		formatInt32(a.TransactionID), // int32
		formatInt32(a.ProtocolID),    // int32
		formatInt32(a.Length),        // int32
		formatInt32(a.UnitID),        // int32
		hex.EncodeToString(a.Payload),
		strconv.FormatBool(a.Exception),
		formatInt32(a.FunctionCode),
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

func (a Modbus) Time() string {
	return a.Timestamp
}

func (a Modbus) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var modbusTcpMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_Modbus.String()),
		Help: Type_NC_Modbus.String() + " audit records",
	},
	fieldsModbus[1:],
)

func init() {
	prometheus.MustRegister(modbusTcpMetric)
}

func (a Modbus) Inc() {
	modbusTcpMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *Modbus) SetPacketContext(ctx *PacketContext) {
	a.Context = ctx
}

func (a Modbus) Src() string {
	if a.Context != nil {
		return a.Context.SrcIP
	}
	return ""
}

func (a Modbus) Dst() string {
	if a.Context != nil {
		return a.Context.DstIP
	}
	return ""
}
