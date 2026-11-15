package kerberosaudit

import (
	"encoding/asn1"
	"testing"

	"github.com/jcmturner/gokrb5/v8/messages"
	krbtypes "github.com/jcmturner/gokrb5/v8/types"
)

func TestKRBSafeRecognitionAndRecord(t *testing.T) {
	message := messages.KRBSafe{PVNO: 5, MsgType: 20, SafeBody: messages.KRBSafeBody{UserData: []byte("synthetic safe data"), SAddress: krbtypes.HostAddress{AddrType: 2, Address: []byte{192, 0, 2, 1}}}, Cksum: krbtypes.Checksum{CksumType: 15, Checksum: []byte{1, 2, 3, 4}}}
	wire, err := asn1.MarshalWithParams(message, "application,explicit,tag:20")
	if err != nil {
		t.Fatal(err)
	}
	if !Decoder.CanDecode(wire, nil) {
		t.Fatal("KRB-SAFE not selected")
	}
	records := (&kerberosReader{}).parseKerberosMessages(wire)
	if len(records) != 1 || records[0].MessageTypeCode != 20 || records[0].MessageType != "KRB-SAFE" || records[0].ClientName != "" || records[0].Realm != "" {
		t.Fatal(records)
	}
	for n := 0; n < len(wire); n++ {
		if len((&kerberosReader{}).parseKerberosMessages(wire[:n])) != 0 {
			t.Fatalf("accepted truncated SAFE at %d", n)
		}
	}
	message.PVNO = 4
	wire, err = asn1.MarshalWithParams(message, "application,explicit,tag:20")
	if err != nil {
		t.Fatal(err)
	}
	if len((&kerberosReader{}).parseKerberosMessages(wire)) != 0 {
		t.Fatal("invalid SAFE version accepted")
	}
}
