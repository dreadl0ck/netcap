package bacnet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type PDU struct {
	Version, Control             uint8
	NetworkMessage, ExpectsReply bool
	Priority                     uint8
	DNET, SNET                   *uint16      `json:",omitempty"`
	DADR, SADR                   string       `json:",omitempty"`
	HopCount                     *uint8       `json:",omitempty"`
	NetworkType                  *uint8       `json:",omitempty"`
	VendorID                     *uint16      `json:",omitempty"`
	APDU                         *Application `json:",omitempty"`
	ApplicationOffset            int          `json:"-"`
}

type Application struct {
	Type                                              uint8
	Name                                              string
	InvokeID, Service                                 *uint8 `json:",omitempty"`
	ServiceName                                       string `json:",omitempty"`
	Segmented, MoreFollows, SegmentedResponseAccepted bool
	Sequence, Window                                  *uint8  `json:",omitempty"`
	Reason                                            *uint8  `json:",omitempty"`
	ObjectID, PropertyID, ArrayIndex, DeviceInstance  *uint32 `json:",omitempty"`
	ErrorClass, ErrorCode                             *uint32 `json:",omitempty"`
	BodyLength                                        int
	Qualifications                                    []string `json:",omitempty"`
}

func ParseNPDU(data []byte) (*PDU, error) {
	if len(data) < 2 || len(data) > 65535 || data[0] != 1 {
		return nil, fmt.Errorf("invalid BACnet NPDU version/length")
	}
	p := &PDU{Version: data[0], Control: data[1], NetworkMessage: data[1]&0x80 != 0, ExpectsReply: data[1]&4 != 0, Priority: data[1] & 3}
	offset := 2
	address := func(network **uint16, address *string) error {
		if len(data)-offset < 3 {
			return fmt.Errorf("short BACnet routed address")
		}
		n := binary.BigEndian.Uint16(data[offset:])
		length := int(data[offset+2])
		offset += 3
		if length > len(data)-offset {
			return fmt.Errorf("BACnet routed address exceeds NPDU")
		}
		*network = &n
		*address = hex.EncodeToString(data[offset : offset+length])
		offset += length
		return nil
	}
	if p.Control&0x20 != 0 {
		if err := address(&p.DNET, &p.DADR); err != nil {
			return nil, err
		}
	}
	if p.Control&8 != 0 {
		if err := address(&p.SNET, &p.SADR); err != nil {
			return nil, err
		}
	}
	if p.DNET != nil {
		if offset == len(data) {
			return nil, fmt.Errorf("BACnet NPDU hop count missing")
		}
		hop := data[offset]
		offset++
		p.HopCount = &hop
	}
	if offset == len(data) {
		return nil, fmt.Errorf("BACnet NPDU body missing")
	}
	if p.NetworkMessage {
		kind := data[offset]
		offset++
		p.NetworkType = &kind
		if kind >= 0x80 {
			if len(data)-offset < 2 {
				return nil, fmt.Errorf("BACnet network vendor ID missing")
			}
			vendor := binary.BigEndian.Uint16(data[offset:])
			p.VendorID = &vendor
		}
		return p, nil
	}
	p.ApplicationOffset = offset
	a, err := parseApplication(data[offset:])
	if err != nil {
		return nil, err
	}
	p.APDU = a
	return p, nil
}

func parseApplication(data []byte) (*Application, error) {
	if len(data) == 0 || data[0]>>4 > 7 {
		return nil, fmt.Errorf("invalid BACnet APDU type")
	}
	a := &Application{Type: data[0] >> 4}
	a.Name = []string{"Confirmed-Request", "Unconfirmed-Request", "Simple-ACK", "Complex-ACK", "Segment-ACK", "Error", "Reject", "Abort"}[a.Type]
	header := 0
	byteAt := func(index int) *uint8 { value := data[index]; return &value }
	switch a.Type {
	case 0, 3:
		a.Segmented = data[0]&8 != 0
		a.MoreFollows = data[0]&4 != 0
		header = 3
		if a.Type == 0 {
			header++
			a.SegmentedResponseAccepted = data[0]&2 != 0
		}
		if a.Segmented {
			header += 2
		}
		if len(data) < header || a.MoreFollows && !a.Segmented {
			return nil, fmt.Errorf("short or inconsistent BACnet segmented APDU")
		}
		invoke := 1
		if a.Type == 0 {
			invoke = 2
		}
		a.InvokeID = byteAt(invoke)
		if a.Segmented {
			a.Sequence = byteAt(invoke + 1)
			a.Window = byteAt(invoke + 2)
		}
		a.Service = byteAt(header - 1)
	case 1:
		header = 2
		if len(data) < header {
			return nil, fmt.Errorf("short BACnet unconfirmed APDU")
		}
		a.Service = byteAt(1)
	case 2, 5, 6, 7:
		header = 3
		if len(data) < header {
			return nil, fmt.Errorf("short BACnet reply APDU")
		}
		a.InvokeID = byteAt(1)
		if a.Type == 2 || a.Type == 5 {
			a.Service = byteAt(2)
		} else {
			a.Reason = byteAt(2)
		}
	case 4:
		header = 4
		if len(data) < header {
			return nil, fmt.Errorf("short BACnet segment ACK")
		}
		a.InvokeID = byteAt(1)
		a.Sequence = byteAt(2)
		a.Window = byteAt(3)
	}
	a.BodyLength = len(data) - header
	if a.Service != nil {
		a.ServiceName = serviceName(a.Type, *a.Service)
	}
	if a.Segmented {
		a.Qualifications = append(a.Qualifications, "BACnet-APDU-segment-not-reassembled")
		return a, nil
	}
	if a.Type == 0 && a.Service != nil && (*a.Service == 12 || *a.Service == 15) {
		if !parseProperty(a, data[header:]) {
			a.Qualifications = append(a.Qualifications, "BACnet-property-fields-incomplete")
		}
	}
	if a.Type == 1 && a.Service != nil && *a.Service == 0 {
		if !parseIAm(a, data[header:]) {
			a.Qualifications = append(a.Qualifications, "BACnet-I-Am-fields-incomplete")
		}
	}
	if a.Type == 5 {
		body := data[header:]
		var values []*uint32
		for range 2 {
			tag, context, value, rest, ok := primitive(body)
			if !ok || context || tag != 9 {
				break
			}
			n := number(value)
			if n == nil {
				break
			}
			values = append(values, n)
			body = rest
		}
		if len(values) == 2 {
			a.ErrorClass, a.ErrorCode = values[0], values[1]
		}
	}
	if a.BodyLength > 0 && a.ObjectID == nil && a.DeviceInstance == nil {
		a.Qualifications = append(a.Qualifications, "BACnet-service-body-not-decoded")
	}
	return a, nil
}

func serviceName(kind, service uint8) string {
	if kind == 1 {
		return map[uint8]string{0: "I-Am", 1: "I-Have", 2: "Unconfirmed-COV-Notification", 3: "Unconfirmed-Event-Notification", 4: "Unconfirmed-Private-Transfer", 5: "Unconfirmed-Text-Message", 6: "Time-Synchronization", 7: "Who-Has", 8: "Who-Is", 9: "UTC-Time-Synchronization", 10: "Write-Group"}[service]
	}
	return map[uint8]string{0: "Acknowledge-Alarm", 1: "Confirmed-COV-Notification", 2: "Confirmed-Event-Notification", 5: "Subscribe-COV", 6: "Atomic-Read-File", 7: "Atomic-Write-File", 8: "Add-List-Element", 9: "Remove-List-Element", 10: "Create-Object", 11: "Delete-Object", 12: "Read-Property", 13: "Read-Property-Conditional", 14: "Read-Property-Multiple", 15: "Write-Property", 16: "Write-Property-Multiple", 17: "Device-Communication-Control", 18: "Confirmed-Private-Transfer", 19: "Confirmed-Text-Message", 20: "Reinitialize-Device", 21: "VT-Open", 22: "VT-Close", 23: "VT-Data", 26: "Read-Range", 27: "Life-Safety-Operation", 28: "Subscribe-COV-Property"}[service]
}

func primitive(data []byte) (tag uint8, context bool, value []byte, rest []byte, ok bool) {
	if len(data) == 0 {
		return
	}
	tag, context = data[0]>>4, data[0]&8 != 0
	length := int(data[0] & 7)
	offset := 1
	if tag == 15 {
		if len(data) < 2 {
			return
		}
		tag = data[1]
		offset++
	}
	if length >= 6 {
		return
	}
	if length == 5 {
		if offset == len(data) {
			return
		}
		length = int(data[offset])
		offset++
		if length == 254 {
			if len(data)-offset < 2 {
				return
			}
			length = int(binary.BigEndian.Uint16(data[offset:]))
			offset += 2
		} else if length == 255 {
			if len(data)-offset < 4 {
				return
			}
			n := binary.BigEndian.Uint32(data[offset:])
			if n > 65535 {
				return
			}
			length = int(n)
			offset += 4
		}
	}
	if length > len(data)-offset {
		return
	}
	return tag, context, data[offset : offset+length], data[offset+length:], true
}

func number(data []byte) *uint32 {
	if len(data) < 1 || len(data) > 4 {
		return nil
	}
	var value uint32
	for _, b := range data {
		value = value<<8 | uint32(b)
	}
	return &value
}

func parseProperty(a *Application, data []byte) bool {
	var values [3]*uint32
	for tag := uint8(0); tag < 2; tag++ {
		kind, context, value, rest, ok := primitive(data)
		if !ok || !context || kind != tag {
			return false
		}
		n := number(value)
		if n == nil || tag == 0 && len(value) != 4 {
			return false
		}
		values[tag] = n
		data = rest
	}
	if len(data) > 0 && data[0]>>4 == 2 && data[0]&8 != 0 {
		_, _, value, rest, ok := primitive(data)
		if !ok {
			return false
		}
		values[2] = number(value)
		if values[2] == nil {
			return false
		}
		data = rest
	}
	a.ObjectID, a.PropertyID, a.ArrayIndex = values[0], values[1], values[2]
	if len(data) > 0 {
		a.Qualifications = append(a.Qualifications, "BACnet-property-value-not-decoded")
	}
	return true
}

func parseIAm(a *Application, data []byte) bool {
	var instance uint32
	for _, want := range []uint8{12, 2, 9, 2} {
		tag, context, value, rest, ok := primitive(data)
		if !ok || context || tag != want {
			return false
		}
		n := number(value)
		if n == nil {
			return false
		}
		if want == 12 {
			if len(value) != 4 || *n>>22 != 8 {
				return false
			}
			instance = *n & 0x3fffff
		}
		data = rest
	}
	if len(data) != 0 {
		return false
	}
	a.DeviceInstance = &instance
	return true
}
