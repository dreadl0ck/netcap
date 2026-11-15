package modbus

import "testing"

func TestOffPortHeuristicDoesNotClaimResponseOnlyBinary(t *testing.T) {
	// A binary prefix can be a complete, valid coil response without identifying its protocol.
	response := []byte{4, 0, 0, 0, 0, 4, 0, 1, 1, 0xff}
	if !CanDecodeOnPort(nil, response) {
		t.Fatal("registered-port response parsing regressed")
	}
	if Decoder.CanDecode(nil, response) {
		t.Fatal("ambiguous binary claimed by off-port Modbus heuristic")
	}
	request := []byte{4, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 8}
	if !Decoder.CanDecode(request, response) || !Decoder.CanDecode(request, nil) {
		t.Fatal("valid Modbus request evidence lost")
	}
}
