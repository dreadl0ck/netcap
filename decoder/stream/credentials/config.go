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
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// HarvesterConfig represents the configuration for a single credential harvester
type HarvesterConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Ports       []int                  `yaml:"ports" json:"ports"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// CustomHarvesterConfig represents configuration for a custom regex-based harvester
type CustomHarvesterConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Ports       []int                  `yaml:"ports" json:"ports"`
	Regex       string                 `yaml:"regex" json:"regex"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// HarvestersConfigFile represents the entire harvesters configuration file structure
type HarvestersConfigFile struct {
	Harvesters       []HarvesterConfig       `yaml:"harvesters" json:"harvesters"`
	CustomHarvesters []CustomHarvesterConfig `yaml:"custom_harvesters,omitempty" json:"custom_harvesters,omitempty"`
}

// LoadHarvestersConfig loads harvester configuration from a YAML file
func LoadHarvestersConfig(path string) (*HarvestersConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read harvesters config file: %w", err)
	}

	var config HarvestersConfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse harvesters config YAML: %w", err)
	}

	return &config, nil
}

// SaveHarvestersConfig saves harvester configuration to a YAML file
func SaveHarvestersConfig(path string, config *HarvestersConfigFile) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal harvesters config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write harvesters config file: %w", err)
	}

	return nil
}

// GetDefaultHarvestersConfig returns the default harvester configuration
func GetDefaultHarvestersConfig() *HarvestersConfigFile {
	return &HarvestersConfigFile{
		Harvesters: []HarvesterConfig{
			{
				Name:        "FTP",
				Description: "FTP plaintext authentication",
				Enabled:     true,
				Ports:       []int{21},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "HTTP",
				Description: "HTTP Basic Auth and Digest, plus sensitive URL parameters",
				Enabled:     true,
				Ports:       []int{80, 8080, 3000, 9090, 8888},
				Parameters: map[string]interface{}{
					"sensitive_params":  []interface{}{"key", "token", "api_key", "apikey", "secret", "password", "pwd", "pass", "auth", "access_token", "refresh_token"},
					"sensitive_headers": []interface{}{"Authorization", "X-API-Key", "X-Auth-Token", "X-Access-Token"},
					"session_cookie_names": []interface{}{
						"PHPSESSID", "phpsessid", "JSESSIONID", "jsessionid",
						"ASP.NET_SessionId", "ASPSESSIONId", "sessionid", "session",
						"_session_id", "connect.sid", "express.sid", "sid",
						"SESSION", "SESSIONID", "sess", "SESS",
						"auth_token", "authtoken", "auth", "token", "access_token",
					},
					"min_cookie_length": 8,
				},
			},
			{
				Name:        "SMTP",
				Description: "SMTP AUTH plaintext and authentication",
				Enabled:     true,
				Ports:       []int{25, 465, 587},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "Telnet",
				Description: "Telnet plaintext login credentials",
				Enabled:     true,
				Ports:       []int{23},
				Parameters: map[string]interface{}{
					"login_patterns":    []interface{}{"login:", "username:", "Username:", "login as:", "Login:"},
					"password_patterns": []interface{}{"Password:", "password:", "Pass:", "passwd:"},
				},
			},
			{
				Name:        "IMAP",
				Description: "IMAP email authentication",
				Enabled:     true,
				Ports:       []int{143},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "NTLMSSP",
				Description: "NTLM Security Support Provider authentication",
				Enabled:     true,
				Ports:       []int{445},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "Kerberos AS-REQ",
				Description: "Kerberos AS-REQ tickets for authentication",
				Enabled:     true,
				Ports:       []int{88},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "Kerberos AS-REP",
				Description: "Kerberos AS-REP tickets with encrypted data",
				Enabled:     true,
				Ports:       []int{88},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "Kerberos TGS-REP",
				Description: "Kerberos TGS-REP tickets for Kerberoasting",
				Enabled:     true,
				Ports:       []int{88},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "HTTP NTLM",
				Description: "HTTP NTLM authentication with base64 encoding",
				Enabled:     true,
				Ports:       []int{80, 8080, 3000, 9090, 8888},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "POP3",
				Description: "POP3 email authentication",
				Enabled:     true,
				Ports:       []int{110, 995},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "Redis",
				Description: "Redis AUTH command authentication",
				Enabled:     true,
				Ports:       []int{6379},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "SNMP",
				Description: "SNMP community strings",
				Enabled:     true,
				Ports:       []int{161, 162},
				Parameters: map[string]interface{}{
					"min_community_length": 1,
					"max_community_length": 255,
				},
			},
			{
				Name:        "LDAP",
				Description: "LDAP Simple Bind authentication",
				Enabled:     true,
				Ports:       []int{389, 636},
				Parameters: map[string]interface{}{
					"username_attributes":     []interface{}{"cn", "uid", "mail", "sAMAccountName"},
					"extract_simple_username": true,
				},
			},
			{
				Name:        "PostgreSQL",
				Description: "PostgreSQL plaintext and MD5 hash authentication",
				Enabled:     true,
				Ports:       []int{5432},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "PostgreSQL Hash",
				Description: "PostgreSQL MD5 password hashes",
				Enabled:     true,
				Ports:       []int{5432},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "MySQL",
				Description: "MySQL challenge-response authentication",
				Enabled:     true,
				Ports:       []int{3306},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "VNC",
				Description: "VNC DES challenge-response authentication",
				Enabled:     true,
				Ports:       []int{5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "MongoDB",
				Description: "MongoDB SCRAM-SHA authentication",
				Enabled:     true,
				Ports:       []int{27017},
				Parameters:  map[string]interface{}{},
			},
			{
				Name:        "MongoDB Challenge Response",
				Description: "MongoDB wire protocol authentication",
				Enabled:     true,
				Ports:       []int{27017},
				Parameters:  map[string]interface{}{},
			},
		},
		CustomHarvesters: []CustomHarvesterConfig{},
	}
}
