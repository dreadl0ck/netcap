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
)

func (a CiscoDiscoveryInfo) CSVHeader() []string {
	return filter([]string{
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
	})
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
		a.CDPHello.ToString(),              //  *CDPHello
		a.DeviceID,                         //  string
		strings.Join(a.Addresses, "|"),     //  []string
		a.PortID,                           //  string
		a.Capabilities.ToString(),          //  *CDPCapabilities
		a.Version,                          //  string
		a.Platform,                         //  string
		strings.Join(ipNets, "|"),          //  []*IPNet
		a.VTPDomain,                        //  string
		formatInt32(a.NativeVLAN),          //  int32
		strconv.FormatBool(a.FullDuplex),   //  bool
		a.VLANReply.ToString(),             //  *CDPVLANDialogue
		a.VLANQuery.ToString(),             //  *CDPVLANDialogue
		formatInt32(a.PowerConsumption),    //  int32
		formatUint32(a.MTU),                //  uint32
		formatInt32(a.ExtendedTrust),       //  int32
		formatInt32(a.UntrustedCOS),        //  int32
		a.SysName,                          //  string
		a.SysOID,                           //  string
		strings.Join(a.MgmtAddresses, "|"), //  []string
		a.Location.ToString(),              //  *CDPLocation
		a.PowerRequest.ToString(),          //  *CDPPowerDialogue
		a.PowerAvailable.ToString(),        //  *CDPPowerDialogue
		a.SparePairPoe.ToString(),          //  *CDPSparePairPoE
		a.EnergyWise.ToString(),            //  *CDPEnergyWise
		strings.Join(vals, "|"),            //  []*CiscoDiscoveryValue
	})
}

func (a CiscoDiscoveryInfo) NetcapTimestamp() string {
	return a.Timestamp
}

func (c CDPHello) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(hex.EncodeToString(c.OUI)) // []byte
	b.WriteString(sep)
	b.WriteString(formatInt32(c.ProtocolID)) // int32
	b.WriteString(sep)
	b.WriteString(c.ClusterMaster) // string
	b.WriteString(sep)
	b.WriteString(c.Unknown1) // string
	b.WriteString(sep)
	b.WriteString(formatInt32(c.Version)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(c.SubVersion)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(c.Status)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(c.Unknown2)) // int32
	b.WriteString(sep)
	b.WriteString(c.ClusterCommander) // string
	b.WriteString(sep)
	b.WriteString(c.SwitchMAC) // string
	b.WriteString(sep)
	b.WriteString(formatInt32(c.Unknown3)) // int32
	b.WriteString(sep)
	b.WriteString(formatInt32(c.ManagementVLAN)) // int32
	b.WriteString(end)

	return b.String()
}

func (c CDPCapabilities) ToString() string {

	var b strings.Builder

	b.WriteString(begin)

	b.WriteString(strconv.FormatBool(c.L3Router)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.TBBridge)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.SPBridge)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.L2Switch)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.IsHost)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.IGMPFilter)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.L1Repeater)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.IsPhone)) // bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.RemotelyManaged)) // bool
	b.WriteString(end)

	return b.String()
}

func (i IPNet) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(i.IP)
	b.WriteString(sep)
	b.WriteString(i.IPMask)
	b.WriteString(end)

	return b.String()
}

func (c CDPVLANDialogue) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(c.ID))
	b.WriteString(sep)
	b.WriteString(formatInt32(c.VLAN))
	b.WriteString(end)

	return b.String()
}

func (c CDPPowerDialogue) ToString() string {

	var vals []string
	for _, v := range c.Values {
		vals = append(vals, formatUint32(v))
	}

	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(c.ID))
	b.WriteString(sep)
	b.WriteString(formatInt32(c.MgmtID))
	b.WriteString(sep)
	b.WriteString(strings.Join(vals, "|"))
	b.WriteString(end)

	return b.String()
}

func (c CDPSparePairPoE) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(strconv.FormatBool(c.PSEFourWire)) //  bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.PDArchShared)) //  bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.PDRequestOn)) //  bool
	b.WriteString(sep)
	b.WriteString(strconv.FormatBool(c.PSEOn)) //  bool
	b.WriteString(end)

	return b.String()
}

func (c CDPEnergyWise) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(hex.EncodeToString(c.EncryptedData)) // []byte
	b.WriteString(sep)
	b.WriteString(formatUint32(c.Unknown1)) // uint32
	b.WriteString(sep)
	b.WriteString(formatUint32(c.SequenceNumber)) // uint32
	b.WriteString(sep)
	b.WriteString(c.ModelNumber) // string
	b.WriteString(sep)
	b.WriteString(formatInt32(c.Unknown2)) // int32
	b.WriteString(sep)
	b.WriteString(c.HardwareID) // string
	b.WriteString(sep)
	b.WriteString(c.SerialNum) // string
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(c.Unknown3)) // []byte
	b.WriteString(sep)
	b.WriteString(c.Role) // string
	b.WriteString(sep)
	b.WriteString(c.Domain) // string
	b.WriteString(sep)
	b.WriteString(c.Name) // string
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown1)) // []byte
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(c.ReplyPort)) // []byte
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(c.ReplyAddress)) // []byte
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown2)) // []byte
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(c.ReplyUnknown3)) // []byte
	b.WriteString(end)

	return b.String()
}

func (c CDPLocation) ToString() string {

	var b strings.Builder

	b.WriteString(begin)
	b.WriteString(formatInt32(c.Type))
	b.WriteString(sep)
	b.WriteString(c.Location)
	b.WriteString(end)

	return b.String()
}
