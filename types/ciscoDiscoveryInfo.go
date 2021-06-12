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
	"github.com/dreadl0ck/netcap/encoder"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	fieldCDPHello         = "CDPHello"
	fieldDeviceID         = "DeviceID"
	fieldAddresses        = "Addresses"
	fieldPortID           = "PortID"
	fieldCapabilities     = "Capabilities"
	fieldPlatform         = "Platform"
	fieldIPPrefixes       = "IPPrefixes"
	fieldVTPDomain        = "VTPDomain"
	fieldNativeVLAN       = "NativeVLAN"
	fieldFullDuplex       = "FullDuplex"
	fieldVLANReply        = "VLANReply"
	fieldVLANQuery        = "VLANQuery"
	fieldPowerConsumption = "PowerConsumption"
	fieldMTU              = "MTU"
	fieldExtendedTrust    = "ExtendedTrust"
	fieldUntrustedCOS     = "UntrustedCOS"
	fieldSysName          = "SysName"
	fieldSysOID           = "SysOID"
	fieldMgmtAddresses    = "MgmtAddresses"
	fieldLocation         = "Location"
	fieldPowerRequest     = "PowerRequest"
	fieldPowerAvailable   = "PowerAvailable"
	fieldSparePairPoe     = "SparePairPoe"
	fieldEnergyWise       = "EnergyWise"
	fieldUnknown          = "Unknown"
)

var fieldsCiscoDiscoveryInfo = []string{
	fieldTimestamp,
	fieldCDPHello,         // *CDPHello
	fieldDeviceID,         // string
	fieldAddresses,        // []string
	fieldPortID,           // string
	fieldCapabilities,     // *CDPCapabilities
	fieldVersion,          // string
	fieldPlatform,         // string
	fieldIPPrefixes,       // []*IPNet
	fieldVTPDomain,        // string
	fieldNativeVLAN,       // int32
	fieldFullDuplex,       // bool
	fieldVLANReply,        // *CDPVLANDialogue
	fieldVLANQuery,        // *CDPVLANDialogue
	fieldPowerConsumption, // int32
	fieldMTU,              // uint32
	fieldExtendedTrust,    // int32
	fieldUntrustedCOS,     // int32
	fieldSysName,          // string
	fieldSysOID,           // string
	fieldMgmtAddresses,    // []string
	fieldLocation,         // *CDPLocation
	fieldPowerRequest,     // *CDPPowerDialogue
	fieldPowerAvailable,   // *CDPPowerDialogue
	fieldSparePairPoe,     // *CDPSparePairPoE
	fieldEnergyWise,       // *CDPEnergyWise
	fieldUnknown,          // []*CiscoDiscoveryValue
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
func (a *CiscoDiscoveryInfo) Time() int64 {
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
	// convert unix timestamp from nano to millisecond precision for elastic
	a.Timestamp /= int64(time.Millisecond)

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

var ciscoDiscoveryInfoEncoder = encoder.NewValueEncoder()

// Encode will encode categorical values and normalize according to configuration
func (a *CiscoDiscoveryInfo) Encode() []string {

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
		ciscoDiscoveryInfoEncoder.Int64(fieldTimestamp, a.Timestamp),
		ciscoDiscoveryInfoEncoder.String(fieldCDPHello, a.CDPHello.toString()),             //  *CDPHello
		ciscoDiscoveryInfoEncoder.String(fieldDeviceID, a.DeviceID),                        //  string
		ciscoDiscoveryInfoEncoder.String(fieldAddresses, join(a.Addresses...)),             //  []string
		ciscoDiscoveryInfoEncoder.String(fieldPortID, a.PortID),                            //  string
		ciscoDiscoveryInfoEncoder.String(fieldCapabilities, a.Capabilities.toString()),     //  *CDPCapabilities
		ciscoDiscoveryInfoEncoder.String(fieldVersion, a.Version),                          //  string
		ciscoDiscoveryInfoEncoder.String(fieldPlatform, a.Platform),                        //  string
		ciscoDiscoveryInfoEncoder.String(fieldIPPrefixes, join(ipNets...)),                 //  []*IPNet
		ciscoDiscoveryInfoEncoder.String(fieldVTPDomain, a.VTPDomain),                      //  string
		ciscoDiscoveryInfoEncoder.Int32(fieldNativeVLAN, a.NativeVLAN),                     //  int32
		ciscoDiscoveryInfoEncoder.Bool(a.FullDuplex),                                       //  bool
		ciscoDiscoveryInfoEncoder.String(fieldVLANReply, a.VLANReply.toString()),           //  *CDPVLANDialogue
		ciscoDiscoveryInfoEncoder.String(fieldVLANQuery, a.VLANQuery.toString()),           //  *CDPVLANDialogue
		ciscoDiscoveryInfoEncoder.Int32(fieldPowerConsumption, a.PowerConsumption),         //  int32
		ciscoDiscoveryInfoEncoder.Uint32(fieldMTU, a.MTU),                                  //  uint32
		ciscoDiscoveryInfoEncoder.Int32(fieldExtendedTrust, a.ExtendedTrust),               //  int32
		ciscoDiscoveryInfoEncoder.Int32(fieldUntrustedCOS, a.UntrustedCOS),                 //  int32
		ciscoDiscoveryInfoEncoder.String(fieldSysName, a.SysName),                          //  string
		ciscoDiscoveryInfoEncoder.String(fieldSysOID, a.SysOID),                            //  string
		ciscoDiscoveryInfoEncoder.String(fieldMgmtAddresses, join(a.MgmtAddresses...)),     //  []string
		ciscoDiscoveryInfoEncoder.String(fieldLocation, a.Location.toString()),             //  *CDPLocation
		ciscoDiscoveryInfoEncoder.String(fieldPowerRequest, a.PowerRequest.toString()),     //  *CDPPowerDialogue
		ciscoDiscoveryInfoEncoder.String(fieldPowerAvailable, a.PowerAvailable.toString()), //  *CDPPowerDialogue
		ciscoDiscoveryInfoEncoder.String(fieldSparePairPoe, a.SparePairPoe.toString()),     //  *CDPSparePairPoE
		ciscoDiscoveryInfoEncoder.String(fieldEnergyWise, a.EnergyWise.toString()),         //  *CDPEnergyWise
		ciscoDiscoveryInfoEncoder.String(fieldUnknown, join(vals...)),                      //  []*CiscoDiscoveryValue
	})
}

// Analyze will invoke the configured analyzer for the audit record and return a score.
func (a *CiscoDiscoveryInfo) Analyze() {

}

// NetcapType returns the type of the current audit record
func (a *CiscoDiscoveryInfo) NetcapType() Type {
	return Type_NC_CiscoDiscoveryInfo
}
