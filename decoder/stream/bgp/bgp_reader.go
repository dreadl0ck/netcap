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

package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
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

	var buf bytes.Buffer

	for _, d := range b.conversation.Data {
		buf.Write(d.Raw())
	}

	data := buf.Bytes()
	offset := 0

	for offset < len(data)-19 {
		// Look for BGP marker
		if !bytes.Equal(data[offset:offset+16], bgpMarker) {
			offset++
			continue
		}

		// Parse BGP header
		length := int(binary.BigEndian.Uint16(data[offset+16 : offset+18]))
		msgType := data[offset+18]

		if length < 19 || length > 4096 || offset+length > len(data) {
			offset++
			continue
		}

		msgData := data[offset : offset+length]
		msg := b.parseBGPMessage(msgType, msgData)

		if msg != nil {
			msg.SrcIP = b.conversation.ClientIP
			msg.DstIP = b.conversation.ServerIP
			msg.SrcPort = int32(b.conversation.ClientPort)
			msg.DstPort = int32(b.conversation.ServerPort)

			err := Decoder.Writer.Write(msg)
			if err != nil {
				bgpLog.Error("failed to write BGP record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}

		offset += length
	}
}

func (b *bgpReader) parseBGPMessage(msgType uint8, data []byte) *types.BGP {
	if len(data) < 19 {
		return nil
	}

	msg := &types.BGP{
		Timestamp: b.conversation.FirstClientPacket.UnixNano(),
		Length:    int32(binary.BigEndian.Uint16(data[16:18])),
		Type:      int32(msgType),
		TypeName:  getBGPMessageTypeName(msgType),
	}

	payload := data[19:]

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
	if len(data) > 10+optParamLen {
		// Parse optional parameters (capabilities)
		b.parseOptionalParameters(msg, data[10:10+optParamLen])
	}
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
	for offset < len(data)-2 {
		capCode := data[offset]
		capLen := int(data[offset+1])

		cap := &types.BGPCapability{
			Code: int32(capCode),
			Name: getBGPCapabilityName(capCode),
		}
		if offset+2+capLen <= len(data) {
			cap.Value = data[offset+2 : offset+2+capLen]
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
		prefixLen := int(data[offset])
		offset++

		// Calculate number of bytes needed for prefix
		prefixBytes := (prefixLen + 7) / 8

		if offset+prefixBytes > len(data) {
			break
		}

		// Build IP prefix
		ip := make([]byte, 4)
		copy(ip, data[offset:offset+prefixBytes])
		prefix := fmt.Sprintf("%s/%d", net.IP(ip).String(), prefixLen)
		prefixes = append(prefixes, prefix)

		offset += prefixBytes
	}

	return prefixes
}

func (b *bgpReader) parsePathAttributes(msg *types.BGP, data []byte) {
	offset := 0

	for offset < len(data)-3 {
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
			Optional:   flags&0x80 != 0,
			Transitive: flags&0x40 != 0,
			Partial:    flags&0x20 != 0,
			Extended:   flags&0x10 != 0,
			TypeCode:   int32(typeCode),
			TypeName:   getBGPPathAttributeName(typeCode),
			Value:      attrData,
		}
		msg.PathAttributes = append(msg.PathAttributes, attr)

		// Parse specific attributes
		switch typeCode {
		case BGPAttrOrigin:
			if len(attrData) > 0 {
				msg.Origin = int32(attrData[0])
				msg.OriginName = getBGPOriginName(attrData[0])
			}
		case BGPAttrASPath:
			msg.ASPath = b.parseASPath(attrData)
		case BGPAttrNextHop:
			if len(attrData) >= 4 {
				msg.NextHop = net.IP(attrData[:4]).String()
			}
		case BGPAttrMultiExitDisc:
			if len(attrData) >= 4 {
				msg.MED = int32(binary.BigEndian.Uint32(attrData))
			}
		case BGPAttrLocalPref:
			if len(attrData) >= 4 {
				msg.LocalPref = int32(binary.BigEndian.Uint32(attrData))
			}
		case BGPAttrAtomicAggregate:
			msg.AtomicAggregate = true
		case BGPAttrCommunities:
			msg.Communities = b.parseCommunities(attrData)
		}

		offset += attrLen
	}
}

func (b *bgpReader) parseASPath(data []byte) []uint32 {
	var asPath []uint32
	offset := 0

	for offset < len(data)-2 {
		segType := data[offset]
		segLen := int(data[offset+1])
		offset += 2

		// Determine AS size based on capability negotiation
		// For now, try 4-byte first (RFC 6793), fall back to 2-byte
		// AS_SET = 1, AS_SEQUENCE = 2, AS_CONFED_SEQUENCE = 3, AS_CONFED_SET = 4
		if segType >= 1 && segType <= 4 {
			// Try 4-byte ASN first (RFC 6793)
			if offset+segLen*4 <= len(data) {
				for i := 0; i < segLen && offset+4 <= len(data); i++ {
					asn := binary.BigEndian.Uint32(data[offset : offset+4])
					asPath = append(asPath, asn)
					offset += 4
				}
			} else if offset+segLen*2 <= len(data) {
				// Fall back to 2-byte ASN
				for i := 0; i < segLen && offset+2 <= len(data); i++ {
					asn := binary.BigEndian.Uint16(data[offset : offset+2])
					asPath = append(asPath, uint32(asn))
					offset += 2
				}
			} else {
				break
			}
		} else {
			break
		}
	}

	return asPath
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

