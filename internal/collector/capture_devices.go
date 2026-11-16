package collector

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/deviceprofile"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type usbRequest struct {
	value, index, length uint16
	requestType, request byte
	ordinal              uint64
}
type mdbRequest struct {
	command byte
	ordinal uint64
}

func (r *linkReconstructor) expireDevices(ordinal uint64) {
	for key, request := range r.usbRequests {
		if ordinal >= request.ordinal && ordinal-request.ordinal > 4096 {
			delete(r.usbRequests, key)
			r.health.BufferedBytes -= 256
		}
	}
	for key, request := range r.mdbRequests {
		if ordinal >= request.ordinal && ordinal-request.ordinal > 4096 {
			delete(r.mdbRequests, key)
			r.health.BufferedBytes -= 256
		}
	}
}

func (r *linkReconstructor) enrichUSB(p gopacket.Packet, link uint32, ordinal uint64) {
	u, ok := p.Layer(layers.LayerTypeUSB).(*layers.USB)
	if !ok || r.err != nil {
		return
	}
	r.health.LimitBytes, r.health.AssemblyLimit = linkStateLimit, linkAssemblyLimit
	fields := map[string]string{}
	key := fmt.Sprintf("%s/usb:%d:%d/%d", packetview.Scope(p), u.BusID, u.DeviceAddress, u.ID)
	if setup, ok := p.Layer(layers.LayerTypeUSBRequestBlockSetup).(*layers.USBRequestBlockSetup); ok && u.EventType == layers.USBEventTypeSubmit {
		if r.usbRequests == nil {
			r.usbRequests = map[string]usbRequest{}
		}
		if _, exists := r.usbRequests[key]; !exists {
			if len(r.usbRequests) >= 1024 || !r.reserve(256) {
				r.err = fmt.Errorf("USB request/state budget exceeded")
				r.health.BudgetExceeded = true
				return
			}
		}
		r.usbRequests[key] = usbRequest{value: uint16(setup.Value), index: uint16(setup.Index), length: uint16(setup.Length), requestType: byte(setup.RequestType), request: byte(setup.Request), ordinal: ordinal}
	}
	if u.EventType == layers.USBEventTypeComplete {
		request, matched := r.usbRequests[key]
		if matched {
			delete(r.usbRequests, key)
			r.health.BufferedBytes -= 256
			fields["request_capture_ordinal"] = strconv.FormatUint(request.ordinal, 10)
			if u.Status == 0 && request.request == 6 && request.requestType&0x80 != 0 && request.requestType&0x60 == 0 {
				body := u.Payload
				if len(body) > int(request.length) {
					body = body[:request.length]
				}
				var metadata map[string]any
				var err error
				if request.value>>8 == 0x22 {
					metadata, err = deviceprofile.HIDReportDescriptor(body)
				} else {
					metadata, err = deviceprofile.USBDescriptor(byte(request.value>>8), body)
				}
				if err != nil {
					fields["descriptor_status"] = err.Error()
				} else {
					if request.value == 0x0300 {
						delete(metadata, "UTF16String")
						metadata["StringIndex"] = 0
						metadata["Status"] = "language-ID-list"
					}
					data, _ := json.Marshal(metadata)
					fields["descriptor"] = string(data)
				}
			}
		}
	}
	profile := r.profiles.Match(packetview.LogicalInterface(p.Metadata().CaptureInfo), link, int(u.BusID), int(u.DeviceAddress), int(u.EndpointNumber))
	if profile != "" && u.Direction == layers.USBDirectionTypeIn && u.EventType == layers.USBEventTypeComplete && u.Status == 0 && u.TransferType == layers.USBTransportTypeInterrupt && u.Data {
		fields["profile_config_sha256"] = r.profiles.Digest
		metadata, err := deviceprofile.HID(profile, u.Payload)
		if err != nil {
			fields["profile_status"] = err.Error()
		} else {
			data, _ := json.Marshal(metadata)
			fields["device_profile"] = string(data)
		}
	}
	if len(fields) > 0 {
		p.Metadata().CaptureInfo.AncillaryData = append(append([]any(nil), p.Metadata().CaptureInfo.AncillaryData...), &linkaudit.USBMetadata{Fields: fields})
	}
}

func (r *linkReconstructor) enrichDeviceProfile(p gopacket.Packet, f *linkaudit.LinkFrame, ordinal uint64) {
	if r.profiles == nil || r.err != nil {
		return
	}
	iface := packetview.LogicalInterface(p.Metadata().CaptureInfo)
	var metadata map[string]any
	var err error
	switch f.Type {
	case 209:
		bus, _ := strconv.Atoi(f.Fields["bus"])
		address, _ := strconv.ParseUint(f.Fields["address"], 0, 16)
		profile := r.profiles.Match(iface, 209, bus, int(address), 0)
		if profile == "" || f.Fields["event"] == "true" {
			return
		}
		metadata, err = deviceprofile.I2CEEPROM(profile, f.Fields["read"] == "true", f.Payload)
	case 300:
		master := f.Source == "VMC"
		addressText := f.Source
		if master {
			addressText = f.Destination
		}
		address, parseErr := strconv.ParseUint(addressText, 0, 16)
		if parseErr != nil {
			return
		}
		profile := r.profiles.Match(iface, 300, 0, int(address), 0)
		if profile == "" {
			return
		}
		key := fmt.Sprintf("%s/mdb:%d", packetview.Scope(p), address)
		command := byte(255)
		if master {
			value, _ := strconv.Atoi(f.Fields["command"])
			command = byte(value)
			if _, exists := r.mdbRequests[key]; exists {
				delete(r.mdbRequests, key)
				r.health.BufferedBytes -= 256
			}
			if f.Fields["checksum_valid"] == "true" {
				if r.mdbRequests == nil {
					r.mdbRequests = map[string]mdbRequest{}
				}
				if _, exists := r.mdbRequests[key]; !exists {
					if !r.reserve(256) {
						return
					}
				}
				r.mdbRequests[key] = mdbRequest{command: command, ordinal: ordinal}
			}
		} else if request, exists := r.mdbRequests[key]; exists {
			command = request.command
			f.Fields["request_capture_ordinal"] = strconv.FormatUint(request.ordinal, 10)
			delete(r.mdbRequests, key)
			r.health.BufferedBytes -= 256
		}
		data := f.Payload
		if len(data) > 1 {
			if f.Fields["checksum_valid"] != "true" {
				return
			}
			data = data[:len(data)-1]
		}
		metadata, err = deviceprofile.MDB(profile, master, command, data)
	}
	if err != nil {
		f.Qualifications = append(f.Qualifications, "device-profile: "+err.Error())
	} else if metadata != nil {
		data, _ := json.Marshal(metadata)
		f.Fields["device_profile"] = string(data)
		f.Fields["profile_config_sha256"] = r.profiles.Digest
	}
}
