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

var fieldsLLDI = []string{
	"Timestamp",
	"PortDescription",
	"SysName",
	"SysDescription",
	"SysCapabilities",
	"MgmtAddress",
	"OrgTLVs",
	"Unknown",
}

func (l LinkLayerDiscoveryInfo) CSVHeader() []string {
	return filter(fieldsLLDI)
}

func (l LinkLayerDiscoveryInfo) CSVRecord() []string {
	var (
		tlvs   = make([]string, len(l.OrgTLVs))
		values = make([]string, len(l.Unknown))
	)
	for i, v := range l.OrgTLVs {
		tlvs[i] = v.ToString()
	}
	for i, v := range l.Unknown {
		values[i] = v.ToString()
	}
	return filter([]string{
		formatTimestamp(l.Timestamp),
		l.PortDescription,            // string
		l.SysName,                    // string
		l.SysDescription,             // string
		l.SysCapabilities.ToString(), // *LLDPSysCapabilities
		l.MgmtAddress.ToString(),     // *LLDPMgmtAddress
		strings.Join(tlvs, ""),       // []*LLDPOrgSpecificTLV
		strings.Join(values, ""),     // []*LinkLayerDiscoveryValue
	})
}

func (l LinkLayerDiscoveryInfo) NetcapTimestamp() string {
	return l.Timestamp
}

func (lldsc *LLDPSysCapabilities) ToString() string {
	return lldsc.SystemCap.ToString() + lldsc.EnabledCap.ToString()
}

func (lldma *LLDPMgmtAddress) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(lldma.Subtype)) // int32   // byte
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(lldma.Address)) // bytes
	b.WriteString(Separator)
	b.WriteString(formatInt32(lldma.InterfaceSubtype)) // int32   // byte
	b.WriteString(Separator)
	b.WriteString(strconv.FormatUint(uint64(lldma.InterfaceNumber), 10)) // uint32
	b.WriteString(Separator)
	b.WriteString(lldma.OID) // string
	b.WriteString(End)
	return b.String()
}

func (lldst *LLDPOrgSpecificTLV) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(strconv.FormatUint(uint64(lldst.OUI), 10))
	b.WriteString(Separator)
	b.WriteString(formatInt32(lldst.SubType))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(lldst.Info))
	b.WriteString(End)
	return b.String()
}

func (lldv *LinkLayerDiscoveryValue) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(lldv.Type))
	b.WriteString(Separator)
	b.WriteString(formatInt32(lldv.Length))
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(lldv.Value))
	b.WriteString(End)
	return b.String()
}

func (c *LLDPCapabilities) ToString() string {
	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(strconv.FormatBool(c.Other))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.Repeater))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.Bridge))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.WLANAP))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.Router))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.Phone))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.DocSis))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.StationOnly))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.CVLAN))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.SVLAN))
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.TMPR))
	b.WriteString(End)
	return b.String()
}

func (a LinkLayerDiscoveryInfo) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var lldiMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_LinkLayerDiscoveryInfo.String()),
		Help: Type_NC_LinkLayerDiscoveryInfo.String() + " audit records",
	},
	fieldsLLDI[1:],
)

func init() {
	prometheus.MustRegister(lldiMetric)
}

func (a LinkLayerDiscoveryInfo) Inc() {
	lldiMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *LinkLayerDiscoveryInfo) SetPacketContext(ctx *PacketContext) {}
