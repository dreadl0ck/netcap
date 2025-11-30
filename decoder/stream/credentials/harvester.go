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

package credentials

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"

	"github.com/gopacket/gopacket"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
)

const (
	// DecoderName is the name for the credentials decoder
	DecoderName = "Credentials"
)

// HarvesterInfo contains metadata about a credential harvester for API responses
type HarvesterInfo struct {
	Name        string
	Description string
	Ports       []int
}

// credentialHarvester is a function that takes the data of a bi-directional network stream over TCP
// as well as meta information and searches for credentials in the data
// on success a pointer to a types.Credential is returned, nil otherwise.
type credentialHarvester func(data []byte, ident string, ts time.Time) *types.Credentials

// Harvester represents a credential harvester with its function and metadata
type Harvester struct {
	Name          string
	Description   string
	HarvesterFunc credentialHarvester
}

// Harvester definitions are now in their respective protocol files

var (
	// useHarvesters controls whether the harvesters should be invoked or not.
	useHarvesters = false

	// allHarvesters contains all available harvesters (used for lookup)
	allHarvesters = map[string]Harvester{
		// Basic authentication protocols
		"FTP":    ftpHarvester,
		"HTTP":   httpHarvester,
		"SMTP":   smtpHarvester,
		"Telnet": telnetHarvester,
		"IMAP":   imapHarvester,
		"POP3":   pop3Harvester,

		// Windows/Active Directory protocols
		"NTLMSSP":          ntlmsspHarvester,
		"Kerberos AS-REQ":  kerberosASReqHarvester,
		"Kerberos AS-REP":  kerberosASRepHarvester,
		"Kerberos TGS-REP": kerberosTGSRepHarvester,
		"HTTP NTLM":        httpNTLMHarvester,

		// Database protocols
		"Redis":                      redisHarvester,
		"LDAP":                       ldapHarvester,
		"PostgreSQL":                 postgresHarvester,
		"PostgreSQL Hash":            postgresHashHarvester,
		"MySQL":                      mysqlHarvester,
		"MongoDB":                    mongodbHarvester,
		"MongoDB Challenge Response": mongodbChallengeResponseHarvester,

		// Network management
		"SNMP":   snmpHarvester,
		"RADIUS": radiusHarvester,

		// Proxy protocols
		"SOCKS": socksHarvester,

		// VoIP protocols
		"SIP": sipHarvester,

		// IoT protocols
		"MQTT": mqttHarvester,

		// Remote desktop
		"VNC":        vncHarvester,
		"TeamViewer": teamviewerHarvester,

		// Network discovery protocols
		"mDNS": mdnsHarvester,
		"NBNS":    nbnsHarvester,
		"UPnP":    upnpHarvester,
		"WSD":     wsdHarvester,
	}

	// harvesters to be ran against all seen bi-directional communication in a TCP session
	// This is dynamically populated based on configuration
	tcpConnectionHarvesters = []Harvester{}

	// mapped port number to the harvester based on the IANA standards
	// used for the first guess which harvester to use.
	// This is dynamically populated based on configuration
	harvesterPortMapping = map[int]Harvester{}

	// harvesterPorts maps harvester names to their configured ports
	// Used for port filtering to reduce false positives
	harvesterPorts = map[string][]int{}

	// harvesterConfig stores the current harvester configuration
	harvesterConfig *HarvestersConfigFile

	// credStore is used to deduplicate the credentials written to disk
	// it maps an identifier in the format: c.Service + c.User + c.Password
	// to the flow ident where the data was observed.
	credStore   = make(map[string]string)
	credStoreMu sync.Mutex
)

// ResetCredStore clears the credentials deduplication store
// This should be called when resetting state between processing different files
func ResetCredStore() {
	credStoreMu.Lock()
	credStore = make(map[string]string)
	credStoreMu.Unlock()
}

//goland:noinspection GoUnusedFunction
func harvesterDebug(ident string, data []byte, args ...interface{}) {
	fmt.Println(ident, "\n", hex.Dump(data), args)
}

// InitializeHarvesters sets up the harvesters based on the provided configuration
func InitializeHarvesters(config *HarvestersConfigFile) error {
	if config == nil {
		// Use default configuration if none provided
		config = GetDefaultHarvestersConfig()
	}

	harvesterConfig = config

	// Clear existing harvesters
	tcpConnectionHarvesters = []Harvester{}
	harvesterPortMapping = map[int]Harvester{}
	harvesterPorts = map[string][]int{}

	// Build harvesters list and port mappings from config
	for _, hConfig := range config.Harvesters {
		if !hConfig.Enabled {
			continue
		}

		// Lookup harvester from all available harvesters
		harvester, ok := allHarvesters[hConfig.Name]
		if !ok {
			fmt.Printf("Warning: harvester %s not found in available harvesters\n", hConfig.Name)
			continue
		}

		// Add to active harvesters list
		tcpConnectionHarvesters = append(tcpConnectionHarvesters, harvester)

		// Store ports for this harvester (for port filtering)
		harvesterPorts[harvester.Name] = hConfig.Ports

		// Add port mappings
		for _, port := range hConfig.Ports {
			harvesterPortMapping[port] = harvester
		}
	}

	// Handle custom harvesters
	for _, customConfig := range config.CustomHarvesters {
		if !customConfig.Enabled {
			continue
		}

		// Create custom harvester from regex
		customHarvester := createCustomRegexHarvester(customConfig)
		tcpConnectionHarvesters = append(tcpConnectionHarvesters, customHarvester)

		// Store ports for this harvester (for port filtering)
		harvesterPorts[customHarvester.Name] = customConfig.Ports

		// Add port mappings for custom harvester
		for _, port := range customConfig.Ports {
			harvesterPortMapping[port] = customHarvester
		}
	}

	return nil
}

// GetHarvesterConfig returns the current harvester configuration
func GetHarvesterConfig() *HarvestersConfigFile {
	if harvesterConfig == nil {
		return GetDefaultHarvestersConfig()
	}
	return harvesterConfig
}

// createCustomRegexHarvester creates a harvester from a custom regex configuration
func createCustomRegexHarvester(config CustomHarvesterConfig) Harvester {
	return Harvester{
		Name:        config.Name,
		Description: config.Description,
		HarvesterFunc: func(data []byte, ident string, ts time.Time) *types.Credentials {
			// This will be implemented similar to the custom regex in credentials.go
			// For now, return nil - will be enhanced when we integrate with credentials.go
			return nil
		},
	}
}

// RunHarvesters will use the service probes to determine the service type based on the provided banner.
// The banner parameter contains at most HarvesterBannerSize bytes from the stream conversation,
// which is pre-truncated to prevent performance issues when processing large data streams
// (e.g., file transfers, database dumps, video streaming, etc.).
func RunHarvesters(banner []byte, transport gopacket.Flow, ident string, firstPacket time.Time) {
	// only use harvesters when credential audit record type is loaded
	// useHarvesters is set after the custom decoder initialization
	if !useHarvesters {
		return
	}

	// Additional safety check: ensure we don't process more than the configured limit
	// This should already be enforced by createBannerFromConversation, but we add
	// a safeguard here in case the banner is created elsewhere
	if len(banner) > decoderconfig.Instance.HarvesterBannerSize {
		banner = banner[:decoderconfig.Instance.HarvesterBannerSize]
	}

	var (
		found bool
		tried = make(map[string]bool) // Track which harvesters we've already tried
	)

	// convert service port to integer
	dstPort, err := strconv.Atoi(transport.Dst().String())
	if err != nil {
		fmt.Println(err)
	}

	srcPort, err := strconv.Atoi(transport.Src().String())
	if err != nil {
		fmt.Println(err)
	}

	// check if its a well known port and use the harvester for that one
	if h, ok := harvesterPortMapping[dstPort]; ok {
		if creds := h.HarvesterFunc(banner, ident, firstPacket); creds != nil { // write audit record
			WriteCredentials(creds)

			// we found a match and will stop processing
			if decoderconfig.Instance.StopAfterHarvesterMatch {
				found = true
			}
		}
		// save the harvester reference so we dont need to run it again
		tried[h.Name] = true
	}

	if h, ok := harvesterPortMapping[srcPort]; ok {
		if !tried[h.Name] { // Don't run the same harvester twice
			if creds := h.HarvesterFunc(banner, ident, firstPacket); creds != nil { // write audit record
				WriteCredentials(creds)

				// we found a match and will stop processing
				if decoderconfig.Instance.StopAfterHarvesterMatch {
					found = true
				}
			}
			tried[h.Name] = true
		}
	}

	// if we dont have a match yet, match against all available harvesters
	if !found {
		// iterate over all harvesters
		for _, h := range tcpConnectionHarvesters {
			// Skip if we've already tried this harvester
			if tried[h.Name] {
				continue
			}

			// When port filtering is enabled (default), only run harvesters on their configured ports
			if decoderconfig.Instance.HarvesterPortFilter {
				if !harvesterMatchesPort(h.Name, srcPort, dstPort) {
					continue
				}
			}

			// execute harvester
			if creds := h.HarvesterFunc(banner, ident, firstPacket); creds != nil { // write audit record
				WriteCredentials(creds)

				// stop after a match if configured
				if decoderconfig.Instance.StopAfterHarvesterMatch {
					break
				}
			}
		}
	}
}

// harvesterMatchesPort checks if a harvester is configured for the given ports
// When port filtering is enabled (default), harvesters only run on their configured ports
// to prevent false positives from protocol mismatches (e.g., MQTT matching on DNS traffic)
func harvesterMatchesPort(harvesterName string, srcPort, dstPort int) bool {
	ports, ok := harvesterPorts[harvesterName]
	if !ok || len(ports) == 0 {
		// If no ports configured, do NOT run on any port to prevent false positives
		// Harvesters must have explicit port configuration to run
		return false
	}

	for _, port := range ports {
		if port == srcPort || port == dstPort {
			return true
		}
	}
	return false
}

// GetHarvesters returns information about all registered credential harvesters
// including their names, descriptions, and associated port mappings
func GetHarvesters() []HarvesterInfo {
	// If we have a config, use it to return enabled harvesters with their configured ports
	if harvesterConfig != nil {
		result := make([]HarvesterInfo, 0)

		for _, hConfig := range harvesterConfig.Harvesters {
			// Get the harvester to access its description
			harvester, ok := allHarvesters[hConfig.Name]
			if !ok {
				continue
			}

			info := HarvesterInfo{
				Name:        hConfig.Name,
				Description: hConfig.Description,
				Ports:       hConfig.Ports,
			}

			// Use description from harvester if not set in config
			if info.Description == "" {
				info.Description = harvester.Description
			}

			result = append(result, info)
		}

		// Add custom harvesters
		for _, customConfig := range harvesterConfig.CustomHarvesters {
			info := HarvesterInfo{
				Name:        customConfig.Name,
				Description: customConfig.Description,
				Ports:       customConfig.Ports,
			}
			result = append(result, info)
		}

		return result
	}

	// Fallback: Build a map to track which harvesters have which ports
	portsByName := make(map[string][]int)

	// Iterate through port mappings and collect ports for each harvester by name
	for port, h := range harvesterPortMapping {
		portsByName[h.Name] = append(portsByName[h.Name], port)
	}

	// Build result from unique harvesters (use a map to deduplicate)
	seen := make(map[string]bool)
	result := make([]HarvesterInfo, 0)

	// Iterate through all registered harvesters to get their info
	for _, h := range tcpConnectionHarvesters {
		// Skip if we've already added this harvester
		if seen[h.Name] {
			continue
		}
		seen[h.Name] = true

		// Get ports for this harvester, ensuring we always have a slice (not nil)
		ports := portsByName[h.Name]
		if ports == nil {
			ports = []int{} // Empty slice instead of nil
		}

		// Create HarvesterInfo with ports from the mapping
		info := HarvesterInfo{
			Name:        h.Name,
			Description: h.Description,
			Ports:       ports,
		}
		result = append(result, info)
	}

	return result
}
