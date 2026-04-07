/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package discovery

import (
	"bytes"
	"regexp"
	"strings"
	"time"
)

// UPnP device types we're interested in
var upnpDeviceTypeNames = map[string]string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice": "Router/Gateway",
	"urn:schemas-upnp-org:device:WANDevice":             "WAN Device",
	"urn:schemas-upnp-org:device:MediaServer":           "Media Server",
	"urn:schemas-upnp-org:device:MediaRenderer":         "Media Renderer",
	"urn:schemas-upnp-org:device:Basic":                 "Basic Device",
	"upnp:rootdevice": "Root Device",
}

var upnpHeaderServer = regexp.MustCompile(`(?i)Server:\s*(.+?)(?:\r\n|\n|$)`)
var upnpHeaderST = regexp.MustCompile(`(?i)(?:ST|NT):\s*(.+?)(?:\r\n|\n|$)`)

// upnpExtract extracts device type and OS information from UPnP/SSDP traffic.
func upnpExtract(data []byte, ident string, ts time.Time) *DiscoveryResult {
	if len(data) < 20 {
		return nil
	}

	// Check for SSDP message types
	if !bytes.HasPrefix(data, []byte("NOTIFY ")) &&
		!bytes.HasPrefix(data, []byte("M-SEARCH ")) &&
		!bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return nil
	}

	dataStr := string(data)
	var deviceTypes []string
	var os string

	// Extract Server header (contains OS/firmware info)
	if m := upnpHeaderServer.FindStringSubmatch(dataStr); len(m) > 1 {
		os = strings.TrimSpace(m[1])
	}

	// Extract device type from ST/NT header
	if m := upnpHeaderST.FindStringSubmatch(dataStr); len(m) > 1 {
		value := strings.TrimSpace(m[1])
		if desc, ok := upnpDeviceTypeNames[value]; ok {
			deviceTypes = append(deviceTypes, desc)
		}
	}

	if os == "" && len(deviceTypes) == 0 {
		return nil
	}

	return &DiscoveryResult{
		DeviceTypes: deviceTypes,
		OS:          os,
	}
}
