package bacnetip

import (
	"github.com/dreadl0ck/netcap/internal/bacnet"
	"github.com/dreadl0ck/netcap/types"
)

func parseSharedNPDU(msg *types.BACnetIP, data []byte) {
	p, err := bacnet.ParseNPDU(data)
	if err != nil {
		msg.ParseQualifications = append(msg.ParseQualifications, err.Error())
		return
	}
	msg.NPDUVersion, msg.NPDUControl, msg.NPDUPriority = int32(p.Version), int32(p.Control), int32(p.Priority)
	msg.NPDUNetworkLayerMsg, msg.NPDUExpectsReply = p.NetworkMessage, p.ExpectsReply
	if p.DNET != nil {
		msg.DNET = int32(*p.DNET)
		msg.DADR = p.DADR
		msg.HopCount = int32(*p.HopCount)
	}
	if p.SNET != nil {
		msg.SNET = int32(*p.SNET)
		msg.SADR = p.SADR
	}
	if p.NetworkType != nil {
		msg.NetworkMessageType = int32(*p.NetworkType)
		msg.NetworkMessageTypeName = getNetworkMessageTypeName(*p.NetworkType)
		return
	}
	a := p.APDU
	msg.APDUType, msg.APDUTypeName = int32(a.Type), getAPDUTypeName(a.Type)
	msg.IsConfirmed = a.Type == 0
	msg.MoreFollows = a.MoreFollows
	msg.SegmentedResponseAccepted = a.SegmentedResponseAccepted
	if a.Segmented {
		msg.SegmentedMessage = 1
	}
	if a.InvokeID != nil {
		msg.InvokeID = int32(*a.InvokeID)
	}
	if a.Sequence != nil {
		msg.SequenceNumber = int32(*a.Sequence)
	}
	if a.Window != nil {
		msg.ProposedWindowSize = int32(*a.Window)
	}
	if a.Service != nil {
		msg.ServiceChoice = int32(*a.Service)
		if a.Type == 1 {
			msg.ServiceName = getUnconfirmedServiceName(*a.Service)
		} else {
			msg.ServiceName = getConfirmedServiceName(*a.Service)
		}
		if a.Type == 0 {
			msg.IsSecurityRelevant = securityRelevantServices[int(*a.Service)]
			msg.IsCriticalOperation = criticalOperationServices[int(*a.Service)]
		}
	}
	if a.Reason != nil {
		if a.Type == 6 {
			msg.RejectReason = int32(*a.Reason)
		} else {
			msg.AbortReason = int32(*a.Reason)
		}
	}
	if a.ObjectID != nil {
		msg.ObjectType = int32(*a.ObjectID >> 22)
		msg.ObjectInstance = *a.ObjectID & 0x3fffff
		msg.ObjectTypeName = getObjectTypeName(uint16(msg.ObjectType))
	}
	if a.DeviceInstance != nil {
		msg.ObjectType = 8
		msg.ObjectInstance = *a.DeviceInstance
		msg.ObjectTypeName = getObjectTypeName(8)
	}
	integer := func(value *uint32, target *int32) {
		if value != nil {
			if *value <= 0x7fffffff {
				*target = int32(*value)
			} else {
				msg.ParseQualifications = append(msg.ParseQualifications, "BACnet-legacy-integer-overflow")
			}
		}
	}
	integer(a.PropertyID, &msg.PropertyIdentifier)
	integer(a.ArrayIndex, &msg.PropertyArrayIndex)
	integer(a.ErrorClass, &msg.ErrorClass)
	integer(a.ErrorCode, &msg.ErrorCode)
	if a.PropertyID != nil {
		msg.PropertyName = getPropertyName(*a.PropertyID)
	}
	if a.ErrorClass != nil && a.ErrorCode != nil && *a.ErrorClass < 256 && *a.ErrorCode < 256 {
		msg.ErrorName = getErrorName(uint8(*a.ErrorClass), uint8(*a.ErrorCode))
	}
	msg.ParseQualifications = append(msg.ParseQualifications, a.Qualifications...)
}
