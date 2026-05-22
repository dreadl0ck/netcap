/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/resolvers"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerResolveTools registers a generic resolve(kind, value) tool
// plus the dedicated lookup_dhcp_fingerprint tool. Both are session-
// independent enrichment helpers that wrap netcap's resolvers package.
func (s *Server) registerResolveTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("resolve",
				mcplib.WithDescription(
					"Run one of netcap's local resolvers against a value: reverse DNS, "+
						"GeoIP lookup, MAC vendor (OUI), IANA service-by-port, or JA4 "+
						"fingerprint product mapping. All lookups are LOCAL — no outbound "+
						"HTTP. Requires the netcap databases (loaded by `net dbs` or on "+
						"webui startup) to be present on disk."),
				mcplib.WithString("kind",
					mcplib.Description("One of: dns, geoip, mac_vendor, iana_service, ja4, ja4s, ja4h, ja4x, ja4t, ja4ts, ja4tscan."),
					mcplib.Required(),
					mcplib.Enum("dns", "geoip", "mac_vendor", "iana_service",
						"ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4ts", "ja4tscan")),
				mcplib.WithString("value",
					mcplib.Description("Lookup key: an IP for dns/geoip, MAC for mac_vendor, port for iana_service, fingerprint hash for ja4*."),
					mcplib.Required()),
				mcplib.WithString("protocol",
					mcplib.Description("For iana_service only: \"tcp\" or \"udp\" (default tcp).")),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleResolve,
		},
		{
			Tool: mcplib.NewTool("lookup_dhcp_fingerprint",
				mcplib.WithDescription(
					"Resolve a DHCPv4 fingerprint (option list) to a device class via "+
						"netcap's local fingerprint database. With AllowNetwork=true and "+
						"INIT_DHCPFINGERPRINT_API_KEY set, falls through to Fingerbank for "+
						"unknown fingerprints; otherwise returns the local-DB match only "+
						"(or an empty result)."),
				mcplib.WithString("fingerprint",
					mcplib.Description("DHCP option list, comma-separated (e.g. \"1,3,6,15,33,43\")."),
					mcplib.Required()),
				mcplib.WithString("vendor",
					mcplib.Description("Optional Vendor Class Identifier hint.")),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(true), // may hit Fingerbank
			),
			Handler: s.handleLookupDHCPFingerprint,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleResolve(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	kind, err := req.RequireString("kind")
	if err != nil {
		return errResult(err), nil
	}
	value, err := req.RequireString("value")
	if err != nil {
		return errResult(err), nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errResult(fmt.Errorf("value is empty")), nil
	}

	out := map[string]any{"kind": kind, "value": value}
	switch kind {
	case "dns":
		out["names"] = resolvers.LookupDNSNames(value)
		if local := resolvers.LookupDNSNameLocal(value); local != "" {
			out["local"] = local
		}
	case "geoip":
		country, city := resolvers.LookupGeolocation(value)
		out["country"] = country
		out["city"] = city
	case "mac_vendor":
		out["vendor"] = resolvers.LookupManufacturer(value)
	case "iana_service":
		port, pErr := strconv.Atoi(value)
		if pErr != nil {
			return errResult(fmt.Errorf("iana_service value must be a numeric port, got %q", value)), nil
		}
		proto := strings.ToLower(req.GetString("protocol", "tcp"))
		if proto != "tcp" && proto != "udp" {
			return errResult(fmt.Errorf("protocol must be tcp or udp, got %q", proto)), nil
		}
		out["service"] = resolvers.LookupServiceByPort(port, proto)
		out["protocol"] = proto
		out["port"] = port
	case "ja4":
		out["product"] = resolvers.LookupJA4(value)
		if e := resolvers.LookupJA4Entry(value); e != nil {
			out["entry"] = e
		}
	case "ja4s":
		out["product"] = resolvers.LookupJA4S(value)
		if e := resolvers.LookupJA4SEntry(value); e != nil {
			out["entry"] = e
		}
	case "ja4h":
		out["product"] = resolvers.LookupJA4H(value)
		if e := resolvers.LookupJA4HEntry(value); e != nil {
			out["entry"] = e
		}
	case "ja4x":
		out["product"] = resolvers.LookupJA4X(value)
		if e := resolvers.LookupJA4XEntry(value); e != nil {
			out["entry"] = e
		}
	case "ja4t":
		out["product"] = resolvers.LookupJA4T(value)
		if e := resolvers.LookupJA4TEntry(value); e != nil {
			out["entry"] = e
		}
	case "ja4ts":
		out["product"] = resolvers.LookupJA4TS(value)
		if e := resolvers.LookupJA4TSEntry(value); e != nil {
			out["entry"] = e
		}
	case "ja4tscan":
		out["product"] = resolvers.LookupJA4TScan(value)
		if e := resolvers.LookupJA4TScanEntry(value); e != nil {
			out["entry"] = e
		}
	default:
		return errResult(fmt.Errorf("unknown kind %q", kind)), nil
	}
	return jsonResult(out), nil
}

func (s *Server) handleLookupDHCPFingerprint(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	fp, err := req.RequireString("fingerprint")
	if err != nil {
		return errResult(err), nil
	}
	vendor := req.GetString("vendor", "")
	out := map[string]any{
		"fingerprint": fp,
		"vendor":      vendor,
	}
	if local := resolvers.LookupDHCPFingerprintLocal(fp); local != "" {
		out["local"] = local
	}
	// LookupDHCPFingerprint also tries Fingerbank when an API key is set
	// (INIT_DHCPFINGERPRINT_API_KEY env). Honour AllowNetwork to gate
	// the outbound call to match lookup_cve's posture.
	if s.cve != nil && s.cve.enabled { // cve.enabled mirrors AllowNetwork
		res, ferr := resolvers.LookupDHCPFingerprint(fp, vendor, nil)
		if ferr != nil {
			out["error"] = ferr.Error()
		} else if res != nil {
			out["result"] = res
		}
	} else {
		out["note"] = "Network disabled; only local-DB match returned. Pass --allow-fetch to enable Fingerbank."
	}
	return jsonResult(out), nil
}
