package deviceprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitProfilesAndDeviceMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	data := []byte(`{"Profiles":[{"Interface":0,"LinkType":209,"Bus":1,"Address":80,"Profile":"i2c-eeprom16"}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil || len(config.Digest) != 64 || config.Match(0, 209, 1, 80, 0) != "i2c-eeprom16" || config.Match(1, 209, 1, 80, 0) != "" {
		t.Fatal(config, err)
	}
	metadata, err := I2CEEPROM("i2c-eeprom16", false, []byte{0x12, 0x34, 1, 2})
	if err != nil || metadata["AddressPointer"].(uint16) != 0x1234 || metadata["WriteBytes"] != 2 {
		t.Fatal(metadata, err)
	}
	metadata, err = HID("usb-hid-boot-keyboard", []byte{2, 0, 4, 5, 0, 0, 0, 0})
	if err != nil || len(metadata["UsageIDs"].([]uint16)) != 2 {
		t.Fatal(metadata, err)
	}
	for _, bad := range []string{`{"Profiles":[{"LinkType":209,"Profile":"guess-device"}]}`, `{"Profiles":[],"unknown":1}`, `{"Profiles":[]} {}`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("invalid profile configuration accepted", bad)
		}
	}
}

func TestUSBDescriptorsAndHIDBounds(t *testing.T) {
	device := []byte{18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 1, 2, 3, 1}
	fields, err := USBDescriptor(1, device)
	if err != nil || fields["VendorID"].(uint16) != 0x1234 || fields["ProductID"].(uint16) != 0x5678 {
		t.Fatal(fields, err)
	}
	// Report size 8, report count 8, Input item: a 64-bit report.
	fields, err = HIDReportDescriptor([]byte{0x75, 8, 0x95, 8, 0x81, 2})
	if err != nil || fields["Reports"].(map[uint32]map[string]uint32)[0]["InputBits"] != 64 {
		t.Fatal(fields, err)
	}
	for _, data := range [][]byte{{0xfe}, {0xb4}, {0x75}, {0x77, 255, 255, 255, 255, 0x95, 1, 0x81, 2}} {
		if _, err := HIDReportDescriptor(data); err == nil {
			t.Fatal("invalid HID descriptor accepted", data)
		}
	}
}

func FuzzDeviceDescriptorBounds(f *testing.F) {
	f.Add([]byte{0x75, 8, 0x95, 8, 0x81, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		_, _ = HIDReportDescriptor(data)
		for _, kind := range []byte{1, 2, 3} {
			_, _ = USBDescriptor(kind, data)
		}
	})
}
