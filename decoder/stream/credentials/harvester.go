/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
		"FTP":                        ftpHarvester,
		"HTTP":                       httpHarvester,
		"SMTP":                       smtpHarvester,
		"Telnet":                     telnetHarvester,
		"IMAP":                       imapHarvester,
		"NTLMSSP":                    ntlmsspHarvester,
		"Kerberos AS-REQ":            kerberosASReqHarvester,
		"Kerberos AS-REP":            kerberosASRepHarvester,
		"Kerberos TGS-REP":           kerberosTGSRepHarvester,
		"HTTP NTLM":                  httpNTLMHarvester,
		"POP3":                       pop3Harvester,
		"Redis":                      redisHarvester,
		"SNMP":                       snmpHarvester,
		"LDAP":                       ldapHarvester,
		"PostgreSQL":                 postgresHarvester,
		"PostgreSQL Hash":            postgresHashHarvester,
		"MySQL":                      mysqlHarvester,
		"VNC":                        vncHarvester,
		"MongoDB":                    mongodbHarvester,
		"MongoDB Challenge Response": mongodbChallengeResponseHarvester,
	}

	// harvesters to be ran against all seen bi-directional communication in a TCP session
	// This is dynamically populated based on configuration
	tcpConnectionHarvesters = []Harvester{}

	// mapped port number to the harvester based on the IANA standards
	// used for the first guess which harvester to use.
	// This is dynamically populated based on configuration
	harvesterPortMapping = map[int]Harvester{}

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
		tried *Harvester
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
		tried = &h
	}

	if h, ok := harvesterPortMapping[srcPort]; ok {
		if creds := h.HarvesterFunc(banner, ident, firstPacket); creds != nil { // write audit record
			WriteCredentials(creds)

			// we found a match and will stop processing
			if decoderconfig.Instance.StopAfterHarvesterMatch {
				found = true
			}
		}
		// save the harvester reference so we dont need to run it again
		tried = &h
	}

	// if we dont have a match yet, match against all available harvesters
	if !found {
		// iterate over all harvesters
		for _, h := range tcpConnectionHarvesters {
			// if the port based first guess has not been found, do not run this harvester again
			if &h != tried {
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
