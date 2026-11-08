/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// BGP Message Types
const (
	BGPMsgOpen         = 1
	BGPMsgUpdate       = 2
	BGPMsgNotification = 3
	BGPMsgKeepalive    = 4
	BGPMsgRouteRefresh = 5
)

// BGP Path Attribute Type Codes
const (
	BGPAttrOrigin          = 1
	BGPAttrASPath          = 2
	BGPAttrNextHop         = 3
	BGPAttrMultiExitDisc   = 4
	BGPAttrLocalPref       = 5
	BGPAttrAtomicAggregate = 6
	BGPAttrAggregator      = 7
	BGPAttrCommunities     = 8
)

type bgpReader struct {
	conversation *core.ConversationInfo
	asWidth      int
	addPathIPv4  bool
	addPathIPv6  bool
}

// New returns a new BGP reader.
func (b *bgpReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &bgpReader{
		conversation: conversation,
	}
}

// Decode parses BGP messages from the stream.
func (b *bgpReader) Decode() {
	if Decoder.Writer == nil {
		bgpLog.Error("BGP Decoder.Writer is nil")
		return
	}

	b.decodeMessages(func(msg *types.BGP) {
		err := Decoder.Writer.Write(msg)
		if err != nil {
			bgpLog.Error("failed to write BGP record", zap.Error(err))
		} else {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

// Each direction retains at most one RFC 4271 message. Gaps invalidate both
// framing and capability negotiation; they cannot splice a synthetic message.
func (b *bgpReader) decodeMessages(emit func(*types.BGP)) {
	var pending [2][]byte
	var timestamps [2][]int64
	var opened, fourByte [2]bool
	var addPath [2]map[uint32]byte
	for _, fragment := range b.conversation.Data {
		direction := 0
		if core.FromServer(fragment) {
			direction = 1
		}
		if s, ok := fragment.(*core.StreamData); ok && s.HasGap(len(pending[direction]) != 0 || opened[direction]) {
			pending[direction], timestamps[direction] = nil, nil
			opened, fourByte = [2]bool{}, [2]bool{}
			addPath = [2]map[uint32]byte{}
		}
		timestamp := core.FragmentTime(fragment)
		for _, octet := range fragment.Raw() {
			pending[direction] = append(pending[direction], octet)
			timestamps[direction] = append(timestamps[direction], timestamp)
			data := pending[direction]
			if len(data) < 19 {
				continue
			}
			length := int(binary.BigEndian.Uint16(data[16:18]))
			if !bytes.Equal(data[:16], bgpMarker) || length < 19 || length > 4096 {
				pending[direction] = data[1:]
				timestamps[direction] = timestamps[direction][1:]
				continue
			}
			if len(data) < length {
				continue
			}
			b.asWidth = 0
			b.addPathIPv4, b.addPathIPv6 = false, false
			if opened[0] && opened[1] {
				b.asWidth = 2
				if fourByte[0] && fourByte[1] {
					b.asWidth = 4
				}
				b.addPathIPv4 = addPath[direction][0x101]&2 != 0 && addPath[1-direction][0x101]&1 != 0
				b.addPathIPv6 = addPath[direction][0x201]&2 != 0 && addPath[1-direction][0x201]&1 != 0
			}
			msg := b.parseBGPMessage(data[18], data)
			if msg != nil {
				msg.SrcIP, msg.DstIP, msg.SrcPort, msg.DstPort = b.conversation.Endpoints(fragment)
				msg.Timestamp = timestamps[direction][0]
				msg.CommunityID = b.conversation.CommunityID
				if msg.Type == BGPMsgOpen {
					opened[direction], fourByte[direction] = true, false
					addPath[direction] = make(map[uint32]byte)
					for _, capability := range msg.Capabilities {
						if capability.Code == 65 && len(capability.Value) == 4 {
							fourByte[direction] = true
						}
						if capability.Code == 69 {
							for i := 0; i+4 <= len(capability.Value); i += 4 {
								value := capability.Value[i : i+4]
								addPath[direction][uint32(binary.BigEndian.Uint16(value))<<8|uint32(value[2])] = value[3]
							}
						}
					}
				}
				emit(msg)
			}
			pending[direction], timestamps[direction] = nil, nil
		}
	}
}

func (b *bgpReader) parseBGPMessage(msgType uint8, data []byte) *types.BGP {
	if len(data) < 19 {
		return nil
	}

	msg := &types.BGP{
		// Timestamp is assigned from the first observed frame byte.
		Length:   int32(binary.BigEndian.Uint16(data[16:18])),
		Type:     int32(msgType),
		TypeName: getBGPMessageTypeName(msgType),
	}

	payload := data[19:]
	if (msgType == BGPMsgOpen && len(payload) < 10) ||
		(msgType == BGPMsgUpdate && len(payload) < 4) ||
		(msgType == BGPMsgNotification && len(payload) < 2) ||
		(msgType == BGPMsgKeepalive && len(payload) != 0) ||
		(msgType == BGPMsgRouteRefresh && len(payload) != 4) || msgType < 1 || msgType > 5 {
		return nil
	}
	if msgType == BGPMsgOpen && (payload[0] != 4 || len(payload) != 10+int(payload[9])) {
		return nil
	}
	if msgType == BGPMsgUpdate {
		withdrawn := int(binary.BigEndian.Uint16(payload))
		if withdrawn > len(payload)-4 {
			return nil
		}
		attributes := int(binary.BigEndian.Uint16(payload[2+withdrawn:]))
		if attributes > len(payload)-4-withdrawn {
			return nil
		}
	}

	switch msgType {
	case BGPMsgOpen:
		b.parseOpenMessage(msg, payload)
	case BGPMsgUpdate:
		b.parseUpdateMessage(msg, payload)
	case BGPMsgNotification:
		b.parseNotificationMessage(msg, payload)
	case BGPMsgKeepalive:
		// Keepalive has no payload
	case BGPMsgRouteRefresh:
		// Route refresh parsing (optional)
	}

	// Perform security analysis after parsing
	analyzeBGPSecurity(msg)

	return msg
}

func (b *bgpReader) parseOpenMessage(msg *types.BGP, data []byte) {
	if len(data) < 10 {
		return
	}

	msg.Version = int32(data[0])
	msg.MyAS = uint32(binary.BigEndian.Uint16(data[1:3]))
	msg.HoldTime = int32(binary.BigEndian.Uint16(data[3:5]))
	msg.BGPIdentifier = net.IP(data[5:9]).String()

	optParamLen := int(data[9])
	msg.OptionalParamLen = int32(optParamLen)

	if optParamLen > 0 && len(data) >= 10+optParamLen {
		// Parse optional parameters (capabilities)
		b.parseOptionalParameters(msg, data[10:10+optParamLen])
	}

	// Set PeerAS from OPEN message's MyAS (the remote peer's AS)
	msg.PeerAS = msg.MyAS
	msg.PeerRouter = msg.BGPIdentifier
}

func (b *bgpReader) parseOptionalParameters(msg *types.BGP, data []byte) {
	offset := 0
	for offset < len(data)-2 {
		paramType := data[offset]
		paramLen := int(data[offset+1])

		if paramType == 2 && offset+2+paramLen <= len(data) {
			// Capability parameter
			capData := data[offset+2 : offset+2+paramLen]
			b.parseCapabilities(msg, capData)
		}

		offset += 2 + paramLen
	}
}

func (b *bgpReader) parseCapabilities(msg *types.BGP, data []byte) {
	offset := 0
	for offset < len(data)-1 {
		capCode := data[offset]
		capLen := int(data[offset+1])

		if offset+2+capLen > len(data) {
			break
		}

		cap := &types.BGPCapability{
			Code:    int32(capCode),
			Name:    getBGPCapabilityName(capCode),
			IsKnown: isKnownCapability(capCode),
		}
		cap.Value = data[offset+2 : offset+2+capLen]

		// Track unknown capabilities
		if !cap.IsKnown {
			msg.HasUnknownCapability = true
		}

		// Parse specific capabilities
		switch capCode {
		case 1: // Multiprotocol Extensions
			if capLen >= 4 {
				cap.AFI = int32(binary.BigEndian.Uint16(cap.Value[0:2]))
				cap.SAFI = int32(cap.Value[3])
				cap.ParsedValue = fmt.Sprintf("AFI=%d, SAFI=%d", cap.AFI, cap.SAFI)
				// Check if IPv6 is supported
				if cap.AFI == 2 { // IPv6
					msg.IsIPv6 = true
				}
			}
		case 65: // 4-octet AS Number
			if capLen >= 4 {
				cap.FourByteAS = binary.BigEndian.Uint32(cap.Value[0:4])
				cap.ParsedValue = fmt.Sprintf("AS=%d", cap.FourByteAS)
				// Update MyAS if 4-byte AS capability present
				if cap.FourByteAS > 0 {
					msg.MyAS = cap.FourByteAS
				}
			}
		case 64: // Graceful Restart
			if capLen >= 2 {
				time := binary.BigEndian.Uint16(cap.Value[0:2]) & 0x0FFF
				cap.GracefulRestartTime = int32(time)
				for i := 2; i+4 <= len(cap.Value); i += 4 {
					cap.GracefulRestartForwarding = cap.GracefulRestartForwarding || cap.Value[i+3]&0x80 != 0
				}
				cap.ParsedValue = fmt.Sprintf("Time=%d, Forwarding=%v", time, cap.GracefulRestartForwarding)
			}
		case 69: // ADD-PATH
			if capLen >= 4 {
				afi := binary.BigEndian.Uint16(cap.Value[0:2])
				safi := cap.Value[2]
				sendRecv := cap.Value[3]
				cap.AFI = int32(afi)
				cap.SAFI = int32(safi)
				cap.AddPathSend = sendRecv&0x02 != 0
				cap.AddPathReceive = sendRecv&0x01 != 0
				cap.ParsedValue = fmt.Sprintf("AFI=%d, SAFI=%d, Send=%v, Receive=%v",
					afi, safi, cap.AddPathSend, cap.AddPathReceive)
			}
		default:
			if capLen > 0 {
				cap.ParsedValue = fmt.Sprintf("%x", cap.Value)
			}
		}

		msg.Capabilities = append(msg.Capabilities, cap)
		offset += 2 + capLen
	}
}

func (b *bgpReader) parseUpdateMessage(msg *types.BGP, data []byte) {
	if len(data) < 4 {
		return
	}

	offset := 0

	// Withdrawn Routes Length
	withdrawnLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if withdrawnLen > len(data)-offset {
		return
	}

	// Parse withdrawn routes
	if withdrawnLen > 0 && offset+withdrawnLen <= len(data) {
		msg.WithdrawnRoutes = b.parsePrefixes(data[offset : offset+withdrawnLen])
		offset += withdrawnLen
	}

	if offset+2 > len(data) {
		return
	}

	// Total Path Attribute Length
	pathAttrLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if pathAttrLen > len(data)-offset {
		return
	}

	// Parse path attributes
	if pathAttrLen > 0 && offset+pathAttrLen <= len(data) {
		b.parsePathAttributes(msg, data[offset:offset+pathAttrLen])
		offset += pathAttrLen
	}

	// NLRI (Network Layer Reachability Information)
	if offset < len(data) {
		msg.NLRI = b.parsePrefixes(data[offset:])
	}
}

func (b *bgpReader) parsePrefixes(data []byte) []string {
	var prefixes []string
	offset := 0

	for offset < len(data) {
		if b.addPathIPv4 {
			if len(data)-offset < 5 {
				break
			}
			offset += 4
		}
		prefixLen := int(data[offset])
		offset++
		if prefixLen > 32 {
			break
		}

		// Calculate number of bytes needed for prefix
		prefixBytes := (prefixLen + 7) / 8

		if offset+prefixBytes > len(data) {
			break
		}

		// Build IP prefix
		ip := make([]byte, 4)
		copy(ip, data[offset:offset+prefixBytes])
		prefix := (&net.IPNet{IP: net.IP(ip).Mask(net.CIDRMask(prefixLen, 32)), Mask: net.CIDRMask(prefixLen, 32)}).String()
		prefixes = append(prefixes, prefix)

		offset += prefixBytes
	}

	return prefixes
}

func (b *bgpReader) parsePathAttributes(msg *types.BGP, data []byte) {
	offset := 0
	knownTypes := getKnownAttributeTypes()
	var as4Path []uint32

	for offset < len(data)-2 {
		flags := data[offset]
		typeCode := data[offset+1]
		offset += 2

		var attrLen int
		if flags&0x10 != 0 { // Extended length
			if offset+2 > len(data) {
				break
			}
			attrLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > len(data) {
				break
			}
			attrLen = int(data[offset])
			offset++
		}

		if offset+attrLen > len(data) {
			break
		}

		attrData := data[offset : offset+attrLen]

		attr := &types.BGPPathAttribute{
			Optional:    flags&0x80 != 0,
			Transitive:  flags&0x40 != 0,
			Partial:     flags&0x20 != 0,
			Extended:    flags&0x10 != 0,
			TypeCode:    int32(typeCode),
			TypeName:    getBGPPathAttributeNameExt(typeCode),
			Value:       attrData,
			Length:      int32(attrLen),
			IsWellKnown: isWellKnownAttribute(typeCode),
			IsMandatory: isMandatoryAttribute(typeCode),
		}

		// Track unknown attributes
		if !knownTypes[typeCode] {
			msg.HasUnknownAttribute = true
			msg.UnknownAttrTypes = append(msg.UnknownAttrTypes, int32(typeCode))
		}

		// Parse specific attributes
		switch typeCode {
		case BGPAttrOrigin:
			if len(attrData) > 0 {
				msg.Origin = int32(attrData[0])
				msg.OriginName = getBGPOriginName(attrData[0])
				attr.ParsedValue = msg.OriginName
			}
		case BGPAttrASPath:
			msg.ASPath, msg.ASPathSet, msg.ASPathConfedSeq, msg.ASPathConfedSet = b.parseASPathExtended(attrData)
			attr.ParsedValue = joinUint32s(msg.ASPath)
		case BGPAttrNextHop:
			if len(attrData) >= 4 {
				msg.NextHop = net.IP(attrData[:4]).String()
				attr.ParsedValue = msg.NextHop
			}
		case BGPAttrMultiExitDisc:
			if len(attrData) >= 4 {
				msg.MED = int32(binary.BigEndian.Uint32(attrData))
				attr.ParsedValue = fmt.Sprintf("%d", msg.MED)
			}
		case BGPAttrLocalPref:
			if len(attrData) >= 4 {
				msg.LocalPref = int32(binary.BigEndian.Uint32(attrData))
				attr.ParsedValue = fmt.Sprintf("%d", msg.LocalPref)
			}
		case BGPAttrAtomicAggregate:
			msg.AtomicAggregate = true
			msg.IsAggregated = true
			attr.ParsedValue = "ATOMIC_AGGREGATE"
		case BGPAttrAggregator:
			// Assume 4-byte AS if AS path contains 4-byte values
			is4ByteAS := len(attrData) >= 8
			msg.AggregatorAS, msg.AggregatorIP = parseAggregator(attrData, is4ByteAS)
			msg.IsAggregated = true
			attr.ParsedValue = fmt.Sprintf("AS%s:%s", msg.AggregatorAS, msg.AggregatorIP)
		case BGPAttrCommunities:
			msg.Communities = b.parseCommunities(attrData)
			attr.ParsedValue = strings.Join(msg.Communities, ", ")
		case BGPAttrExtCommunities: // Extended Communities (type 16)
			msg.ExtendedCommunities = parseExtendedCommunities(attrData)
			attr.ParsedValue = strings.Join(msg.ExtendedCommunities, ", ")
		case BGPAttrLargeCommunity: // Large Communities (type 32)
			msg.LargeCommunities = parseLargeCommunities(attrData)
			attr.ParsedValue = strings.Join(msg.LargeCommunities, ", ")
		case BGPAttrMPReachNLRI: // MP_REACH_NLRI (type 14)
			b.parseMPReachNLRI(msg, attrData)
			attr.ParsedValue = "MP_REACH_NLRI"
		case BGPAttrMPUnreachNLRI: // MP_UNREACH_NLRI (type 15)
			b.parseMPUnreachNLRI(msg, attrData)
			attr.ParsedValue = "MP_UNREACH_NLRI"
		case BGPAttrAS4Path: // AS4_PATH (type 17)
			var set, confed, confedSet []uint32
			as4Path, set, confed, confedSet = parseASPathWidth(attrData, 4)
			attr.ParsedValue = joinUint32s(as4Path)
			if len(set)+len(confed)+len(confedSet) > 0 {
				as4Path = nil
			}
		case BGPAttrAS4Aggregator: // AS4_AGGREGATOR (type 18)
			msg.AggregatorAS, msg.AggregatorIP = parseAggregator(attrData, true)
			attr.ParsedValue = fmt.Sprintf("AS%s:%s", msg.AggregatorAS, msg.AggregatorIP)
		}

		msg.PathAttributes = append(msg.PathAttributes, attr)
		offset += attrLen
	}
	// Attribute wire order is immaterial. Retain the leading legacy sequence;
	// do not flatten AS_SET/confederation semantics into an invented sequence.
	if b.asWidth != 4 && len(msg.ASPathSet)+len(msg.ASPathConfedSeq)+len(msg.ASPathConfedSet) == 0 &&
		len(as4Path) > 0 && len(as4Path) <= len(msg.ASPath) {
		msg.ASPath = append(msg.ASPath[:len(msg.ASPath)-len(as4Path)], as4Path...)
	}
}

func (b *bgpReader) parseASPath(data []byte) []uint32 {
	asPath, _, _, _ := b.parseASPathExtended(data)
	return asPath
}

// parseASPathExtended parses AS path with segment type awareness
// Returns: AS_SEQUENCE, AS_SET, AS_CONFED_SEQUENCE, AS_CONFED_SET
func (b *bgpReader) parseASPathExtended(data []byte) ([]uint32, []uint32, []uint32, []uint32) {
	if b.asWidth == 2 || b.asWidth == 4 {
		return parseASPathWidth(data, b.asWidth)
	}
	// Midstream captures have no negotiation witness. Only accept an
	// unambiguous complete encoding, never guess width from bytes remaining.
	a, s, c, d := parseASPathWidth(data, 2)
	e, f, g, h := parseASPathWidth(data, 4)
	valid2 := len(a)+len(s)+len(c)+len(d) > 0
	valid4 := len(e)+len(f)+len(g)+len(h) > 0
	if valid2 && !valid4 {
		return a, s, c, d
	}
	if valid4 && !valid2 {
		return e, f, g, h
	}
	return nil, nil, nil, nil
}

func parseASPathWidth(data []byte, asSize int) ([]uint32, []uint32, []uint32, []uint32) {
	var asSequence, asSet, asConfedSeq, asConfedSet []uint32
	offset := 0

	for offset < len(data) {
		if offset+2 > len(data) {
			return nil, nil, nil, nil
		}
		segType := data[offset]
		segLen := int(data[offset+1])
		offset += 2

		if segLen == 0 || segType < 1 || segType > 4 || offset+segLen*asSize > len(data) {
			return nil, nil, nil, nil
		}

		var segmentASes []uint32
		for range segLen {
			if offset+asSize > len(data) {
				break
			}
			var asn uint32
			if asSize == 4 {
				asn = binary.BigEndian.Uint32(data[offset : offset+4])
			} else {
				asn = uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
			}
			segmentASes = append(segmentASes, asn)
			offset += asSize
		}

		// Assign to appropriate segment type
		switch segType {
		case ASSegTypeSet: // AS_SET = 1
			asSet = append(asSet, segmentASes...)
		case ASSegTypeSequence: // AS_SEQUENCE = 2
			asSequence = append(asSequence, segmentASes...)
		case ASSegTypeConfedSeq: // AS_CONFED_SEQUENCE = 3
			asConfedSeq = append(asConfedSeq, segmentASes...)
		case ASSegTypeConfedSet: // AS_CONFED_SET = 4
			asConfedSet = append(asConfedSet, segmentASes...)
		}
	}

	return asSequence, asSet, asConfedSeq, asConfedSet
}

// parseMPReachNLRI parses MP_REACH_NLRI attribute for IPv6 support
func (b *bgpReader) parseMPReachNLRI(msg *types.BGP, data []byte) {
	if len(data) < 5 {
		return
	}

	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	nextHopLen := int(data[3])

	offset := 4

	// Parse next hop
	if afi == 2 && nextHopLen > 0 && offset+nextHopLen <= len(data) { // IPv6
		msg.IsIPv6 = true
		if nextHopLen >= 16 {
			msg.IPv6NextHop = net.IP(data[offset : offset+16]).String()
		}
		offset += nextHopLen
	} else {
		offset += nextHopLen
	}

	// Skip reserved byte
	if offset < len(data) {
		offset++
	}

	// Parse NLRI
	if afi == 2 && safi == 1 && offset < len(data) { // IPv6 Unicast
		msg.IPv6NLRI = b.parseIPv6Prefixes(data[offset:])
	}
}

// parseMPUnreachNLRI parses MP_UNREACH_NLRI attribute for IPv6 withdrawals
func (b *bgpReader) parseMPUnreachNLRI(msg *types.BGP, data []byte) {
	if len(data) < 3 {
		return
	}

	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]

	if afi == 2 && safi == 1 && len(data) > 3 { // IPv6 Unicast
		msg.IsIPv6 = true
		msg.IPv6Withdrawn = b.parseIPv6Prefixes(data[3:])
	}
}

// parseIPv6Prefixes parses IPv6 prefixes from NLRI data
func (b *bgpReader) parseIPv6Prefixes(data []byte) []string {
	var prefixes []string
	offset := 0

	for offset < len(data) {
		if b.addPathIPv6 {
			if len(data)-offset < 5 {
				break
			}
			offset += 4
		}
		if offset >= len(data) {
			break
		}
		prefixLen := int(data[offset])
		offset++
		if prefixLen > 128 {
			break
		}

		// Calculate number of bytes needed for prefix
		prefixBytes := (prefixLen + 7) / 8

		if offset+prefixBytes > len(data) {
			break
		}

		// Build IPv6 prefix
		ip := make([]byte, 16)
		copy(ip, data[offset:offset+prefixBytes])
		prefix := (&net.IPNet{IP: net.IP(ip).Mask(net.CIDRMask(prefixLen, 128)), Mask: net.CIDRMask(prefixLen, 128)}).String()
		prefixes = append(prefixes, prefix)

		offset += prefixBytes
	}

	return prefixes
}

// joinUint32s joins a slice of uint32 into a comma-separated string
func joinUint32s(values []uint32) string {
	if len(values) == 0 {
		return ""
	}
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(strs, ",")
}

func (b *bgpReader) parseCommunities(data []byte) []string {
	var communities []string

	for i := 0; i+4 <= len(data); i += 4 {
		high := binary.BigEndian.Uint16(data[i : i+2])
		low := binary.BigEndian.Uint16(data[i+2 : i+4])
		communities = append(communities, fmt.Sprintf("%d:%d", high, low))
	}

	return communities
}

func (b *bgpReader) parseNotificationMessage(msg *types.BGP, data []byte) {
	if len(data) < 2 {
		return
	}

	msg.ErrorCode = int32(data[0])
	msg.ErrorCodeName = getBGPErrorCodeName(data[0])
	msg.ErrorSubcode = int32(data[1])
	msg.ErrorSubcodeName = getBGPErrorSubcodeName(data[0], data[1])

	if len(data) > 2 {
		msg.NotificationData = data[2:]
	}
}

func getBGPMessageTypeName(msgType uint8) string {
	switch msgType {
	case BGPMsgOpen:
		return "OPEN"
	case BGPMsgUpdate:
		return "UPDATE"
	case BGPMsgNotification:
		return "NOTIFICATION"
	case BGPMsgKeepalive:
		return "KEEPALIVE"
	case BGPMsgRouteRefresh:
		return "ROUTE-REFRESH"
	default:
		return "UNKNOWN"
	}
}

func getBGPPathAttributeName(typeCode uint8) string {
	return getBGPPathAttributeNameExt(typeCode)
}

// getBGPPathAttributeNameExt returns extended attribute type names
func getBGPPathAttributeNameExt(typeCode uint8) string {
	switch typeCode {
	case BGPAttrOrigin:
		return "ORIGIN"
	case BGPAttrASPath:
		return "AS_PATH"
	case BGPAttrNextHop:
		return "NEXT_HOP"
	case BGPAttrMultiExitDisc:
		return "MULTI_EXIT_DISC"
	case BGPAttrLocalPref:
		return "LOCAL_PREF"
	case BGPAttrAtomicAggregate:
		return "ATOMIC_AGGREGATE"
	case BGPAttrAggregator:
		return "AGGREGATOR"
	case BGPAttrCommunities:
		return "COMMUNITIES"
	case 9:
		return "ORIGINATOR_ID"
	case 10:
		return "CLUSTER_LIST"
	case BGPAttrMPReachNLRI:
		return "MP_REACH_NLRI"
	case BGPAttrMPUnreachNLRI:
		return "MP_UNREACH_NLRI"
	case BGPAttrExtCommunities:
		return "EXTENDED_COMMUNITIES"
	case BGPAttrAS4Path:
		return "AS4_PATH"
	case BGPAttrAS4Aggregator:
		return "AS4_AGGREGATOR"
	case 22:
		return "PMSI_TUNNEL"
	case 23:
		return "TUNNEL_ENCAPSULATION"
	case 24:
		return "TRAFFIC_ENGINEERING"
	case 25:
		return "IPV6_EXTENDED_COMMUNITIES"
	case 26:
		return "AIGP"
	case 27:
		return "PE_DISTINGUISHER_LABELS"
	case 28:
		return "BGP_LS"
	case BGPAttrLargeCommunity:
		return "LARGE_COMMUNITY"
	case 33:
		return "BGPSEC_PATH"
	case 34:
		return "ONLY_TO_CUSTOMER"
	case 35:
		return "BGP_DOMAIN_PATH"
	case 36:
		return "SFP_ATTRIBUTE"
	case 37:
		return "BFD_DISCRIMINATOR"
	case 40:
		return "BGP_PREFIX_SID"
	case 128:
		return "ATTR_SET"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", typeCode)
	}
}

func getBGPOriginName(origin uint8) string {
	switch origin {
	case 0:
		return "IGP"
	case 1:
		return "EGP"
	case 2:
		return "INCOMPLETE"
	default:
		return "UNKNOWN"
	}
}

func getBGPCapabilityName(code uint8) string {
	switch code {
	case 1:
		return "Multiprotocol Extensions"
	case 2:
		return "Route Refresh"
	case 64:
		return "Graceful Restart"
	case 65:
		return "4-octet AS Number"
	case 69:
		return "ADD-PATH"
	case 70:
		return "Enhanced Route Refresh"
	default:
		return fmt.Sprintf("Unknown(%d)", code)
	}
}

func getBGPErrorCodeName(code uint8) string {
	switch code {
	case 1:
		return "Message Header Error"
	case 2:
		return "OPEN Message Error"
	case 3:
		return "UPDATE Message Error"
	case 4:
		return "Hold Timer Expired"
	case 5:
		return "Finite State Machine Error"
	case 6:
		return "Cease"
	default:
		return "Unknown"
	}
}

func getBGPErrorSubcodeName(code, subcode uint8) string {
	switch code {
	case 1: // Message Header Error
		switch subcode {
		case 1:
			return "Connection Not Synchronized"
		case 2:
			return "Bad Message Length"
		case 3:
			return "Bad Message Type"
		}
	case 2: // OPEN Message Error
		switch subcode {
		case 1:
			return "Unsupported Version Number"
		case 2:
			return "Bad Peer AS"
		case 3:
			return "Bad BGP Identifier"
		case 4:
			return "Unsupported Optional Parameter"
		case 6:
			return "Unacceptable Hold Time"
		}
	case 6: // Cease
		switch subcode {
		case 1:
			return "Maximum Number of Prefixes Reached"
		case 2:
			return "Administrative Shutdown"
		case 3:
			return "Peer De-configured"
		case 4:
			return "Administrative Reset"
		case 5:
			return "Connection Rejected"
		case 6:
			return "Other Configuration Change"
		}
	}
	return fmt.Sprintf("Subcode %d", subcode)
}
