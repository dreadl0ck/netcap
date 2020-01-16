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

var fieldsCiscoDiscoveryInfo = []string{
	"Timestamp",
	"CDPHello",         // *CDPHello
	"DeviceID",         // string
	"Addresses",        // []string
	"PortID",           // string
	"Capabilities",     // *CDPCapabilities
	"Version",          // string
	"Platform",         // string
	"IPPrefixes",       // []*IPNet
	"VTPDomain",        // string
	"NativeVLAN",       // int32
	"FullDuplex",       // bool
	"VLANReply",        // *CDPVLANDialogue
	"VLANQuery",        // *CDPVLANDialogue
	"PowerConsumption", // int32
	"MTU",              // uint32
	"ExtendedTrust",    // int32
	"UntrustedCOS",     // int32
	"SysName",          // string
	"SysOID",           // string
	"MgmtAddresses",    // []string
	"Location",         // *CDPLocation
	"PowerRequest",     // *CDPPowerDialogue
	"PowerAvailable",   // *CDPPowerDialogue
	"SparePairPoe",     // *CDPSparePairPoE
	"EnergyWise",       // *CDPEnergyWise
	"Unknown",          // []*CiscoDiscoveryValue
}

func (a CiscoDiscoveryInfo) CSVHeader() []string {
	return filter(fieldsCiscoDiscoveryInfo)
}

func (a CiscoDiscoveryInfo) CSVRecord() []string {
	var (
		ipNets []string
		vals   []string
	)
	for _, v := range a.IPPrefixes {
		ipNets = append(ipNets, v.ToString())
	}
	for _, v := range a.Unknown {
		vals = append(vals, v.ToString())
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.CDPHello.ToString(),            //  *CDPHello
		a.DeviceID,                       //  string
		join(a.Addresses...),             //  []string
		a.PortID,                         //  string
		a.Capabilities.ToString(),        //  *CDPCapabilities
		a.Version,                        //  string
		a.Platform,                       //  string
		join(ipNets...),                  //  []*IPNet
		a.VTPDomain,                      //  string
		formatInt32(a.NativeVLAN),        //  int32
		strconv.FormatBool(a.FullDuplex), //  bool
		a.VLANReply.ToString(),           //  *CDPVLANDialogue
		a.VLANQuery.ToString(),           //  *CDPVLANDialogue
		formatInt32(a.PowerConsumption),  //  int32
		formatUint32(a.MTU),              //  uint32
		formatInt32(a.ExtendedTrust),     //  int32
		formatInt32(a.UntrustedCOS),      //  int32
		a.SysName,                        //  string
		a.SysOID,                         //  string
		join(a.MgmtAddresses...),         //  []string
		a.Location.ToString(),            //  *CDPLocation
		a.PowerRequest.ToString(),        //  *CDPPowerDialogue
		a.PowerAvailable.ToString(),      //  *CDPPowerDialogue
		a.SparePairPoe.ToString(),        //  *CDPSparePairPoE
		a.EnergyWise.ToString(),          //  *CDPEnergyWise
		join(vals...),                    //  []*CiscoDiscoveryValue
	})
}

func (a CiscoDiscoveryInfo) Time() string {
	return a.Timestamp
}

func (c CDPHello) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(hex.EncodeToString(c.OUI)) // []byte
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.ProtocolID)) // int32
	b.WriteString(Separator)
	b.WriteString(c.ClusterMaster) // string
	b.WriteString(Separator)
	b.WriteString(c.Unknown1) // string
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.Version)) // int32
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.SubVersion)) // int32
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.Status)) // int32
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.Unknown2)) // int32
	b.WriteString(Separator)
	b.WriteString(c.ClusterCommander) // string
	b.WriteString(Separator)
	b.WriteString(c.SwitchMAC) // string
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.Unknown3)) // int32
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.ManagementVLAN)) // int32
	b.WriteString(End)

	return b.String()
}

func (c CDPCapabilities) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)

	b.WriteString(strconv.FormatBool(c.L3Router)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.TBBridge)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.SPBridge)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.L2Switch)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.IsHost)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.IGMPFilter)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.L1Repeater)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.IsPhone)) // bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.RemotelyManaged)) // bool
	b.WriteString(End)

	return b.String()
}

func (i IPNet) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(i.IP)
	b.WriteString(Separator)
	b.WriteString(i.IPMask)
	b.WriteString(End)

	return b.String()
}

func (c CDPVLANDialogue) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(formatInt32(c.ID))
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.VLAN))
	b.WriteString(End)

	return b.String()
}

func (c CDPPowerDialogue) ToString() string {

	var vals []string
	for _, v := range c.Values {
		vals = append(vals, formatUint32(v))
	}

	var b strings.Builder
	b.WriteString(Begin)
	b.WriteString(formatInt32(c.ID))
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.MgmtID))
	b.WriteString(Separator)
	b.WriteString(join(vals...))
	b.WriteString(End)

	return b.String()
}

func (c CDPSparePairPoE) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(strconv.FormatBool(c.PSEFourWire)) //  bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.PDArchShared)) //  bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.PDRequestOn)) //  bool
	b.WriteString(Separator)
	b.WriteString(strconv.FormatBool(c.PSEOn)) //  bool
	b.WriteString(End)

	return b.String()
}

func (c CDPEnergyWise) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(hex.EncodeToString(c.EncryptedData)) // []byte
	b.WriteString(Separator)
	b.WriteString(formatUint32(c.Unknown1)) // uint32
	b.WriteString(Separator)
	b.WriteString(formatUint32(c.SequenceNumber)) // uint32
	b.WriteString(Separator)
	b.WriteString(c.ModelNumber) // string
	b.WriteString(Separator)
	b.WriteString(formatInt32(c.Unknown2)) // int32
	b.WriteString(Separator)
	b.WriteString(c.HardwareID) // string
	b.WriteString(Separator)
	b.WriteString(c.SerialNum) // string
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(c.Unknown3)) // []byte
	b.WriteString(Separator)
	b.WriteString(c.Role) // string
	b.WriteString(Separator)
	b.WriteString(c.Domain) // string
	b.WriteString(Separator)
	b.WriteString(c.Name) // string
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown1)) // []byte
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(c.ReplyPort)) // []byte
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(c.ReplyAddress)) // []byte
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown2)) // []byte
	b.WriteString(Separator)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown3)) // []byte
	b.WriteString(End)

	return b.String()
}

func (c CDPLocation) ToString() string {

	var b strings.Builder

	b.WriteString(Begin)
	b.WriteString(formatInt32(c.Type))
	b.WriteString(Separator)
	b.WriteString(c.Location)
	b.WriteString(End)

	return b.String()
}

func (a CiscoDiscoveryInfo) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var ciscoDiscoveryInfoMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CiscoDiscoveryInfo.String()),
		Help: Type_NC_CiscoDiscoveryInfo.String() + " audit records",
	},
	fieldsCiscoDiscoveryInfo[1:],
)

func init() {
	prometheus.MustRegister(ciscoDiscoveryInfoMetric)
}

func (a CiscoDiscoveryInfo) Inc() {
	ciscoDiscoveryInfoMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *CiscoDiscoveryInfo) SetPacketContext(ctx *PacketContext) {}

// TODO
func (a CiscoDiscoveryInfo) Src() string {
	return ""
}

func (a CiscoDiscoveryInfo) Dst() string {
	return ""
}
