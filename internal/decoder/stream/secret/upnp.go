/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package secret

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceUPnP = "UPnP"

// SSDP/UPnP constants
const (
	ssdpPort      = 1900
	wsdPort       = 3702
	ssdpMulticast = "239.255.255.250"
)

// Common UPnP headers and their extraction patterns
var upnpHeaderPatterns = map[string]*regexp.Regexp{
	"Server":        regexp.MustCompile(`(?i)Server:\s*(.+?)(?:\r\n|\n|$)`),
	"Location":      regexp.MustCompile(`(?i)Location:\s*(.+?)(?:\r\n|\n|$)`),
	"USN":           regexp.MustCompile(`(?i)USN:\s*(.+?)(?:\r\n|\n|$)`),
	"ST":            regexp.MustCompile(`(?i)ST:\s*(.+?)(?:\r\n|\n|$)`),
	"NT":            regexp.MustCompile(`(?i)NT:\s*(.+?)(?:\r\n|\n|$)`),
	"NTS":           regexp.MustCompile(`(?i)NTS:\s*(.+?)(?:\r\n|\n|$)`),
	"Cache-Control": regexp.MustCompile(`(?i)Cache-Control:\s*(.+?)(?:\r\n|\n|$)`),
	"User-Agent":    regexp.MustCompile(`(?i)User-Agent:\s*(.+?)(?:\r\n|\n|$)`),
}

// UPnP device types we're interested in
var upnpDeviceTypes = map[string]string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice": "Router/Gateway",
	"urn:schemas-upnp-org:device:WANDevice":             "WAN Device",
	"urn:schemas-upnp-org:device:MediaServer":           "Media Server",
	"urn:schemas-upnp-org:device:MediaRenderer":         "Media Renderer",
	"urn:schemas-upnp-org:device:Basic":                 "Basic Device",
	"urn:schemas-upnp-org:service:WANIPConnection":      "WAN IP Connection",
	"urn:schemas-upnp-org:service:WANPPPConnection":     "WAN PPP Connection",
	"urn:schemas-upnp-org:service:Layer3Forwarding":     "Layer3 Forwarding",
	"upnp:rootdevice": "Root Device",
	"ssdp:all":        "All Devices",
}

// upnpDeviceInfo contains parsed UPnP device information
type upnpDeviceInfo struct {
	Server     string
	Location   string
	USN        string
	DeviceType string
	DeviceDesc string
	IsNotify   bool
	IsSearch   bool
	IsResponse bool
}

// upnpHarvesterFunc extracts device information from UPnP/SSDP traffic.
// UPnP is used for device discovery and can reveal routers, media servers,
// IoT devices, and other network equipment.
func upnpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	if len(data) < 20 {
		return nil
	}

	// Check for SSDP/UPnP message types
	dataStr := string(data)

	var info upnpDeviceInfo

	// Identify message type
	if bytes.HasPrefix(data, []byte("NOTIFY ")) {
		info.IsNotify = true
	} else if bytes.HasPrefix(data, []byte("M-SEARCH ")) {
		info.IsSearch = true
	} else if bytes.HasPrefix(data, []byte("HTTP/1.")) {
		info.IsResponse = true
	} else {
		// Not a recognized SSDP message
		return nil
	}

	// Extract headers
	for headerName, pattern := range upnpHeaderPatterns {
		if matches := pattern.FindStringSubmatch(dataStr); len(matches) > 1 {
			value := strings.TrimSpace(matches[1])
			switch headerName {
			case "Server":
				info.Server = value
			case "Location":
				info.Location = value
			case "USN":
				info.USN = value
			case "ST", "NT":
				// Device/Service type
				info.DeviceType = value
				if desc, ok := upnpDeviceTypes[value]; ok {
					info.DeviceDesc = desc
				}
			}
		}
	}

	// Only report if we found useful information
	if info.Server == "" && info.Location == "" && info.DeviceType == "" {
		return nil
	}

	// Build device identifier
	var deviceName string
	if info.Server != "" {
		deviceName = info.Server
	} else if info.USN != "" {
		// Extract device name from USN (format: uuid:xxx::urn:schemas...)
		deviceName = extractDeviceFromUSN(info.USN)
	}

	// Format notes
	var notes strings.Builder

	if info.IsNotify {
		notes.WriteString("UPnP NOTIFY - ")
	} else if info.IsSearch {
		notes.WriteString("UPnP M-SEARCH - ")
	} else if info.IsResponse {
		notes.WriteString("UPnP Response - ")
	}

	if info.DeviceDesc != "" {
		notes.WriteString(info.DeviceDesc)
	} else if info.DeviceType != "" {
		notes.WriteString(info.DeviceType)
	}

	if info.Location != "" {
		notes.WriteString(fmt.Sprintf(" | Location: %s", info.Location))
	}

	if info.Server != "" && deviceName != info.Server {
		notes.WriteString(fmt.Sprintf(" | Server: %s", info.Server))
	}

	return &types.Secret{
		Timestamp: ts.UnixNano(),
		Service:   serviceUPnP,
		Flow:      ident,
		User:      deviceName, // Store device identifier
		Password:  "",
		Notes:     notes.String(),
	}
}

// extractDeviceFromUSN extracts a readable device identifier from USN
func extractDeviceFromUSN(usn string) string {
	// USN format: uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx::urn:schemas-upnp-org:...
	// or just: uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

	// Remove "uuid:" prefix if present
	usn = strings.TrimPrefix(usn, "uuid:")

	// Split on "::" to get just the UUID part
	if idx := strings.Index(usn, "::"); idx > 0 {
		usn = usn[:idx]
	}

	// Truncate long UUIDs for display
	if len(usn) > 36 {
		usn = usn[:36]
	}

	return usn
}

// upnpHarvester is the harvester definition for UPnP
var upnpHarvester = Harvester{
	Name:          "UPnP",
	Description:   "Universal Plug and Play - captures device discovery and service announcements",
	HarvesterFunc: upnpHarvesterFunc,
}

// WSD (Web Services Discovery) harvester for Windows devices
const serviceWSD = "WSD"

// wsdHarvesterFunc extracts device information from WS-Discovery traffic.
// WSD is used by Windows for network device discovery.
func wsdHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	if len(data) < 100 {
		return nil
	}

	// Check for SOAP/XML WSD message
	if !bytes.Contains(data, []byte("soap")) && !bytes.Contains(data, []byte("SOAP")) {
		return nil
	}

	// Look for WSD-specific namespaces
	if !bytes.Contains(data, []byte("schemas.xmlsoap.org/ws/2005/04/discovery")) &&
		!bytes.Contains(data, []byte("schemas.xmlsoap.org/ws/2006/02/devprof")) {
		return nil
	}

	// Extract device type from XML
	deviceType := "Unknown"
	if bytes.Contains(data, []byte("Probe")) {
		deviceType = "Discovery Probe"
	} else if bytes.Contains(data, []byte("ProbeMatch")) {
		deviceType = "Discovery Response"
	} else if bytes.Contains(data, []byte("Hello")) {
		deviceType = "Device Announcement"
	} else if bytes.Contains(data, []byte("Bye")) {
		deviceType = "Device Departure"
	}

	// Try to extract device address from XAddrs
	var deviceAddr string
	xAddrsPattern := regexp.MustCompile(`<[^>]*XAddrs[^>]*>([^<]+)<`)
	if matches := xAddrsPattern.FindSubmatch(data); len(matches) > 1 {
		deviceAddr = string(matches[1])
	}

	// Try to extract device type from Types element
	typesPattern := regexp.MustCompile(`<[^>]*Types[^>]*>([^<]+)<`)
	if matches := typesPattern.FindSubmatch(data); len(matches) > 1 {
		typeStr := string(matches[1])
		// Clean up namespace prefixes
		if idx := strings.LastIndex(typeStr, ":"); idx > 0 {
			typeStr = typeStr[idx+1:]
		}
		if typeStr != "" {
			deviceType = fmt.Sprintf("%s (%s)", deviceType, typeStr)
		}
	}

	notes := fmt.Sprintf("Web Services Discovery - %s", deviceType)
	if deviceAddr != "" {
		notes += fmt.Sprintf(" | Address: %s", deviceAddr)
	}

	return &types.Secret{
		Timestamp: ts.UnixNano(),
		Service:   serviceWSD,
		Flow:      ident,
		User:      deviceAddr, // Store device address
		Password:  "",
		Notes:     notes,
	}
}

// wsdHarvester is the harvester definition for WSD
var wsdHarvester = Harvester{
	Name:          "WSD",
	Description:   "Web Services Discovery - captures Windows network device discovery",
	HarvesterFunc: wsdHarvesterFunc,
}
