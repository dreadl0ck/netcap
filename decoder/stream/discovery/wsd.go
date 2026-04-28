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

var wsdTypesPattern = regexp.MustCompile(`<[^>]*Types[^>]*>([^<]+)<`)

// wsdExtract extracts device type information from WS-Discovery traffic.
func wsdExtract(data []byte, ident string, ts time.Time) *DiscoveryResult {
	if len(data) < 100 {
		return nil
	}

	if !bytes.Contains(data, []byte("soap")) && !bytes.Contains(data, []byte("SOAP")) {
		return nil
	}

	if !bytes.Contains(data, []byte("schemas.xmlsoap.org/ws/2005/04/discovery")) &&
		!bytes.Contains(data, []byte("schemas.xmlsoap.org/ws/2006/02/devprof")) {
		return nil
	}

	var deviceTypes []string

	// Extract device type from Types element
	if m := wsdTypesPattern.FindSubmatch(data); len(m) > 1 {
		typeStr := string(m[1])
		if idx := strings.LastIndex(typeStr, ":"); idx > 0 {
			typeStr = typeStr[idx+1:]
		}
		if typeStr != "" {
			deviceTypes = append(deviceTypes, typeStr)
		}
	}

	if len(deviceTypes) == 0 {
		return nil
	}

	return &DiscoveryResult{
		DeviceTypes: deviceTypes,
	}
}
