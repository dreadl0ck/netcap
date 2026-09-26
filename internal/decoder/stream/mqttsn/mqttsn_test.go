package mqttsn

import "testing"

func TestUDPMessageLengthMustMatchDatagram(t *testing.T) {
	// SEARCHGW, length 3 including the header and the radius byte.
	valid := []byte{3, MsgTypeSearchGw, 1}
	if !Decoder.CanDecode(valid, nil) {
		t.Fatal("complete MQTT-SN datagram was rejected")
	}
	if !Decoder.CanDecode(append(append([]byte(nil), valid...), valid...), nil) {
		t.Fatal("two complete MQTT-SN messages in one datagram were rejected")
	}
	for _, payload := range [][]byte{
		{3, MsgTypeSearchGw, 1, 0, 0, 0},
		{8, MsgTypeSearchGw, 1},
	} {
		if Decoder.CanDecode(payload, nil) {
			t.Errorf("accepted declared length %d for a %d-byte datagram", payload[0], len(payload))
		}
	}
}
