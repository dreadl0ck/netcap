package bacnetip

import (
	"github.com/dreadl0ck/netcap/types"
	"testing"
)

func TestSharedNPDUFieldsAndTruncation(t *testing.T) {
	msg := &types.BACnetIP{}
	parseSharedNPDU(msg, []byte{1, 4, 0, 5, 17, 12, 0x0c, 2, 0, 0, 123, 0x19, 85})
	if msg.ObjectType != 8 || msg.ObjectInstance != 123 || msg.PropertyIdentifier != 85 || msg.InvokeID != 17 || msg.ServiceName != "ReadProperty" {
		t.Fatal(msg)
	}
	msg = &types.BACnetIP{}
	parseSharedNPDU(msg, []byte{1, 0, 0, 5, 17})
	if len(msg.ParseQualifications) == 0 || msg.ServiceName != "" {
		t.Fatal("truncation became a service", msg)
	}
}
