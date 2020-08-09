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

// CSVHeader returns the CSV header for the audit record.
func (a *CiscoDiscoveryInfo) CSVHeader() []string {
	return filter(fieldsCiscoDiscoveryInfo)
}

// CSVRecord returns the CSV record for the audit record.
func (a *CiscoDiscoveryInfo) CSVRecord() []string {
	var (
		ipNets []string
		vals   []string
	)

	for _, v := range a.IPPrefixes {
		ipNets = append(ipNets, v.toString())
	}

	for _, v := range a.Unknown {
		vals = append(vals, v.toString())
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.CDPHello.toString(),            //  *CDPHello
		a.DeviceID,                       //  string
		join(a.Addresses...),             //  []string
		a.PortID,                         //  string
		a.Capabilities.toString(),        //  *CDPCapabilities
		a.Version,                        //  string
		a.Platform,                       //  string
		join(ipNets...),                  //  []*IPNet
		a.VTPDomain,                      //  string
		formatInt32(a.NativeVLAN),        //  int32
		strconv.FormatBool(a.FullDuplex), //  bool
		a.VLANReply.toString(),           //  *CDPVLANDialogue
		a.VLANQuery.toString(),           //  *CDPVLANDialogue
		formatInt32(a.PowerConsumption),  //  int32
		formatUint32(a.MTU),              //  uint32
		formatInt32(a.ExtendedTrust),     //  int32
		formatInt32(a.UntrustedCOS),      //  int32
		a.SysName,                        //  string
		a.SysOID,                         //  string
		join(a.MgmtAddresses...),         //  []string
		a.Location.toString(),            //  *CDPLocation
		a.PowerRequest.toString(),        //  *CDPPowerDialogue
		a.PowerAvailable.toString(),      //  *CDPPowerDialogue
		a.SparePairPoe.toString(),        //  *CDPSparePairPoE
		a.EnergyWise.toString(),          //  *CDPEnergyWise
		join(vals...),                    //  []*CiscoDiscoveryValue
	})
}

// Time returns the timestamp associated with the audit record.
func (a *CiscoDiscoveryInfo) Time() string {
	return a.Timestamp
}

func (c *CDPHello) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(hex.EncodeToString(c.OUI)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.ProtocolID)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(c.ClusterMaster) // string
	b.WriteString(FieldSeparator)
	b.WriteString(c.Unknown1) // string
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.Version)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.SubVersion)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.Status)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.Unknown2)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(c.ClusterCommander) // string
	b.WriteString(FieldSeparator)
	b.WriteString(c.SwitchMAC) // string
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.Unknown3)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.ManagementVLAN)) // int32
	b.WriteString(StructureEnd)

	return b.String()
}

func (c *CDPCapabilities) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)

	b.WriteString(strconv.FormatBool(c.L3Router)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.TBBridge)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.SPBridge)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.L2Switch)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.IsHost)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.IGMPFilter)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.L1Repeater)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.IsPhone)) // bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.RemotelyManaged)) // bool
	b.WriteString(StructureEnd)

	return b.String()
}

func (i *IPNet) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(i.IP)
	b.WriteString(FieldSeparator)
	b.WriteString(i.IPMask)
	b.WriteString(StructureEnd)

	return b.String()
}

func (c *CDPVLANDialogue) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(c.ID))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.VLAN))
	b.WriteString(StructureEnd)

	return b.String()
}

func (c *CDPPowerDialogue) toString() string {
	var vals []string

	for _, v := range c.Values {
		vals = append(vals, formatUint32(v))
	}

	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(c.ID))
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.MgmtID))
	b.WriteString(FieldSeparator)
	b.WriteString(join(vals...))
	b.WriteString(StructureEnd)

	return b.String()
}

func (c *CDPSparePairPoE) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(strconv.FormatBool(c.PSEFourWire)) //  bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.PDArchShared)) //  bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.PDRequestOn)) //  bool
	b.WriteString(FieldSeparator)
	b.WriteString(strconv.FormatBool(c.PSEOn)) //  bool
	b.WriteString(StructureEnd)

	return b.String()
}

func (c *CDPEnergyWise) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(hex.EncodeToString(c.EncryptedData)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(c.Unknown1)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(formatUint32(c.SequenceNumber)) // uint32
	b.WriteString(FieldSeparator)
	b.WriteString(c.ModelNumber) // string
	b.WriteString(FieldSeparator)
	b.WriteString(formatInt32(c.Unknown2)) // int32
	b.WriteString(FieldSeparator)
	b.WriteString(c.HardwareID) // string
	b.WriteString(FieldSeparator)
	b.WriteString(c.SerialNum) // string
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(c.Unknown3)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(c.Role) // string
	b.WriteString(FieldSeparator)
	b.WriteString(c.Domain) // string
	b.WriteString(FieldSeparator)
	b.WriteString(c.Name) // string
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown1)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(c.ReplyPort)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(c.ReplyAddress)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown2)) // []byte
	b.WriteString(FieldSeparator)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown3)) // []byte
	b.WriteString(StructureEnd)

	return b.String()
}

func (c *CDPLocation) toString() string {
	var b strings.Builder

	b.WriteString(StructureBegin)
	b.WriteString(formatInt32(c.Type))
	b.WriteString(FieldSeparator)
	b.WriteString(c.Location)
	b.WriteString(StructureEnd)

	return b.String()
}

// JSON returns the JSON representation of the audit record.
func (a *CiscoDiscoveryInfo) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(a)
}

var ciscoDiscoveryInfoMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_CiscoDiscoveryInfo.String()),
		Help: Type_NC_CiscoDiscoveryInfo.String() + " audit records",
	},
	fieldsCiscoDiscoveryInfo[1:],
)

// Inc increments the metrics for the audit record.
func (a *CiscoDiscoveryInfo) Inc() {
	ciscoDiscoveryInfoMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

// SetPacketContext sets the associated packet context for the audit record.
func (a *CiscoDiscoveryInfo) SetPacketContext(*PacketContext) {}

// Src TODO.
// Src returns the source address of the audit record.
func (a *CiscoDiscoveryInfo) Src() string {
	return ""
}

// Dst returns the destination address of the audit record.
func (a *CiscoDiscoveryInfo) Dst() string {
	return ""
}
