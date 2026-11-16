package collector

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/deviceprofile"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/gopacket/gopacket"
)

func TestUSBDescriptorCorrelationAndExplicitHIDProfile(t *testing.T) {
	r := &linkReconstructor{profiles: &deviceprofile.Config{Profiles: []deviceprofile.Rule{{Interface: 0, LinkType: 266, Bus: 26, Address: 7, Endpoint: 1, Profile: "usb-hid-boot-keyboard"}}}}
	feed := func(wire []byte, ordinal uint64) map[string]string {
		p := decodeDarwinUSB(wire)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100, int64(ordinal)), Length: len(wire), CaptureLength: len(wire)}
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer())
		}
		r.enrichUSB(p, 266, ordinal)
		for _, item := range p.Metadata().CaptureInfo.AncillaryData {
			if metadata, ok := item.(*linkaudit.USBMetadata); ok {
				return metadata.Fields
			}
		}
		return nil
	}
	feed(darwinUSBFrame(0, 0, 0, []byte{0x80, 6, 0, 1, 0, 0, 18, 0}), 1)
	fields := feed(darwinUSBFrame(1, 0x80, 0, []byte{18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 1, 2, 3, 1}), 2)
	var descriptor map[string]any
	if err := json.Unmarshal([]byte(fields["descriptor"]), &descriptor); err != nil || descriptor["VendorID"].(float64) != 0x1234 || fields["request_capture_ordinal"] != "1" {
		t.Fatal(fields, err)
	}
	fields = feed(darwinUSBFrame(1, 0x81, 3, []byte{2, 0, 4, 0, 0, 0, 0, 0}), 3)
	if fields["device_profile"] == "" {
		t.Fatal("explicit HID selector did not decode report", fields)
	}
	r.finish()
	if r.health.BufferedBytes != 0 {
		t.Fatal("USB request credits leaked", r.health)
	}
}
