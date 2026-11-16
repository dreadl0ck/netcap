package deviceprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Rule struct {
	Interface              int
	LinkType               uint32
	Bus, Address, Endpoint int
	Profile                string
}
type Config struct {
	Profiles []Rule
	Digest   string `json:"-"`
}

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, fmt.Errorf("device profile configuration exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("device profile configuration has trailing data")
	}
	if len(config.Profiles) > 64 {
		return nil, fmt.Errorf("device profile rule limit exceeded")
	}
	seen := map[[5]int]bool{}
	for _, rule := range config.Profiles {
		if rule.Interface < 0 || rule.Bus < 0 || rule.Bus > 65535 || rule.Address < 0 || rule.Address > 127 || rule.Endpoint < 0 || rule.Endpoint > 127 {
			return nil, fmt.Errorf("invalid device profile selector")
		}
		valid := false
		switch rule.Profile {
		case "i2c-eeprom8", "i2c-eeprom16":
			valid = rule.LinkType == 209 && rule.Bus < 128
		case "mdb-coin-changer":
			valid = rule.LinkType == 300 && rule.Address == 8
		case "mdb-bill-validator":
			valid = rule.LinkType == 300 && rule.Address == 0x30
		case "usb-hid-boot-keyboard", "usb-hid-boot-mouse":
			valid = (rule.LinkType == 189 || rule.LinkType == 220 || rule.LinkType == 249 || rule.LinkType == 266) && rule.Endpoint > 0
		}
		key := [5]int{rule.Interface, int(rule.LinkType), rule.Bus, rule.Address, rule.Endpoint}
		if !valid || seen[key] {
			return nil, fmt.Errorf("unsupported or ambiguous device profile rule")
		}
		seen[key] = true
	}
	config.Digest = fmt.Sprintf("%x", sha256.Sum256(data))
	return &config, nil
}

func (c *Config) Match(iface int, link uint32, bus, address, endpoint int) string {
	if c == nil {
		return ""
	}
	for _, rule := range c.Profiles {
		if rule.Interface == iface && rule.LinkType == link && rule.Bus == bus && rule.Address == address && rule.Endpoint == endpoint {
			return rule.Profile
		}
	}
	return ""
}

func HID(profile string, data []byte) (map[string]any, error) {
	fields := map[string]any{"Profile": profile}
	switch profile {
	case "usb-hid-boot-keyboard":
		if len(data) != 8 || data[1] != 0 {
			return nil, fmt.Errorf("invalid boot keyboard report")
		}
		fields["ModifierMask"] = data[0]
		var usages []uint16
		for _, usage := range data[2:] {
			if usage != 0 {
				usages = append(usages, uint16(usage))
			}
		}
		fields["UsageIDs"] = usages
	case "usb-hid-boot-mouse":
		if len(data) != 3 || data[0]&0xf8 != 0 {
			return nil, fmt.Errorf("invalid boot mouse report")
		}
		fields["Buttons"], fields["DeltaX"], fields["DeltaY"] = data[0], int8(data[1]), int8(data[2])
	default:
		return nil, fmt.Errorf("unsupported HID profile")
	}
	return fields, nil
}

func I2CEEPROM(profile string, read bool, data []byte) (map[string]any, error) {
	fields := map[string]any{"Profile": profile, "Read": read, "TransferBytes": len(data)}
	if read {
		return fields, nil
	}
	width := 1
	if profile == "i2c-eeprom16" {
		width = 2
	} else if profile != "i2c-eeprom8" {
		return nil, fmt.Errorf("unsupported EEPROM profile")
	}
	if len(data) < width {
		return nil, fmt.Errorf("EEPROM address pointer truncated")
	}
	address := uint16(data[0])
	if width == 2 {
		address = binary.BigEndian.Uint16(data)
	}
	fields["AddressPointer"], fields["WriteBytes"] = address, len(data)-width
	return fields, nil
}

func MDB(profile string, master bool, command byte, data []byte) (map[string]any, error) {
	fields := map[string]any{"Profile": profile, "Master": master, "PayloadBytes": len(data)}
	if master {
		names := map[byte]string{0: "Reset", 1: "Setup", 2: "TubeStatus", 3: "Poll", 5: "Dispense"}
		if profile == "mdb-bill-validator" {
			names = map[byte]string{0: "Reset", 1: "Setup", 2: "Security", 3: "Poll", 4: "BillType", 5: "Escrow", 6: "Stacker"}
		}
		fields["Command"], fields["CommandName"] = command, names[command]
		return fields, nil
	}
	if len(data) == 1 {
		fields["ControlReply"] = data[0]
	}
	if command == 1 && profile == "mdb-coin-changer" {
		if len(data) < 23 {
			return nil, fmt.Errorf("coin changer setup response truncated")
		}
		fields["FeatureLevel"], fields["CurrencyCode"], fields["ScalingFactor"], fields["DecimalPlaces"], fields["CoinRoutingMask"] = data[0], binary.BigEndian.Uint16(data[1:]), data[3], data[4], binary.BigEndian.Uint16(data[5:])
		values := make([]uint16, 16)
		for i, value := range data[7:23] {
			values[i] = uint16(value)
		}
		fields["CoinCreditValues"] = values
	}
	if command == 1 && profile == "mdb-bill-validator" {
		if len(data) < 27 {
			return nil, fmt.Errorf("bill validator setup response truncated")
		}
		fields["FeatureLevel"], fields["CurrencyCode"], fields["ScalingFactor"], fields["DecimalPlaces"], fields["StackerCapacity"], fields["SecurityMask"], fields["Escrow"] = data[0], binary.BigEndian.Uint16(data[1:]), binary.BigEndian.Uint16(data[3:]), data[5], binary.BigEndian.Uint16(data[6:]), binary.BigEndian.Uint16(data[8:]), data[10] != 0
		values := make([]uint16, 16)
		for i, value := range data[11:27] {
			values[i] = uint16(value)
		}
		fields["BillCreditValues"] = values
	}
	return fields, nil
}
