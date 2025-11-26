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

// Package injection provides packet manipulation and injection capabilities
// for offensive security testing and network research.
package injection

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/filter"
	"github.com/dreadl0ck/netcap/types"
)

// Action represents the type of injection action to perform.
type Action string

const (
	// ActionAccept forwards the packet unchanged.
	ActionAccept Action = "accept"

	// ActionDrop silently drops the packet.
	ActionDrop Action = "drop"

	// ActionModifyPayload modifies the packet payload using search/replace.
	ActionModifyPayload Action = "modify_payload"

	// ActionInjectPacket injects an additional crafted packet.
	ActionInjectPacket Action = "inject_packet"

	// ActionInjectTCPRST sends a TCP RST to terminate the connection.
	ActionInjectTCPRST Action = "inject_tcp_rst"

	// ActionInjectDNS spoofs a DNS response.
	ActionInjectDNS Action = "inject_dns"

	// ActionInjectARP sends a spoofed ARP reply.
	ActionInjectARP Action = "inject_arp"

	// ActionDelay delays packet forwarding by a specified duration.
	ActionDelay Action = "delay"

	// ActionHTTPInjectHeader injects or modifies HTTP headers.
	ActionHTTPInjectHeader Action = "http_inject_header"

	// ActionHTTPSSLStrip downgrades HTTPS links to HTTP in responses.
	ActionHTTPSSLStrip Action = "http_ssl_strip"

	// ActionHTTPRedirect injects an HTTP redirect response.
	ActionHTTPRedirect Action = "http_redirect"
)

// Rule represents an injection rule that matches packets and performs actions.
type Rule struct {
	// Name is a unique identifier for the rule.
	Name string `yaml:"name"`

	// Description provides human-readable information about the rule.
	Description string `yaml:"description"`

	// Type specifies which audit record type this rule applies to (e.g., "TCP", "HTTP", "DNS").
	Type string `yaml:"type"`

	// Expression is the expr-lang expression to evaluate against packets.
	Expression string `yaml:"expression"`

	// Action specifies what action to perform when the rule matches.
	Action Action `yaml:"action"`

	// ActionConfig contains action-specific configuration parameters.
	ActionConfig map[string]interface{} `yaml:"action_config"`

	// Enabled determines whether this rule is active.
	Enabled bool `yaml:"enabled"`

	// Priority determines rule evaluation order (higher = evaluated first).
	Priority int `yaml:"priority,omitempty"`

	// StopOnMatch if true, stops evaluating further rules after this one matches.
	StopOnMatch bool `yaml:"stop_on_match,omitempty"`

	// Tags are custom labels for categorizing rules.
	Tags []string `yaml:"tags,omitempty"`

	// compiled is the compiled expression program (not serialized).
	compiled *vm.Program
}

// Config holds a collection of injection rules loaded from a YAML file.
type Config struct {
	// Description provides information about this rule set.
	Description string `yaml:"description"`

	// Rules is the list of injection rules.
	Rules []*Rule `yaml:"rules"`
}

// LoadRulesFromFile loads injection rules from a YAML file.
func LoadRulesFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	return &config, nil
}

// LoadRulesFromDirectory loads all rule files from a directory and returns a merged configuration.
func LoadRulesFromDirectory(dirPath string) (*Config, error) {
	config := &Config{
		Rules: []*Rule{},
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())
		fileConfig, err := LoadRulesFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from %s: %w", entry.Name(), err)
		}

		config.Rules = append(config.Rules, fileConfig.Rules...)
	}

	return config, nil
}

// LoadRules loads rules from a path (file or directory).
func LoadRules(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat rules path: %w", err)
	}

	if info.IsDir() {
		return LoadRulesFromDirectory(path)
	}

	return LoadRulesFromFile(path)
}

// CompileRules compiles all rule expressions in the configuration.
func CompileRules(config *Config) error {
	for i, rule := range config.Rules {
		if !rule.Enabled {
			continue
		}

		if rule.Expression == "" {
			return fmt.Errorf("rule %s has empty expression", rule.Name)
		}

		// Convert type string to types.Type
		recordType, err := parseRecordType(rule.Type)
		if err != nil {
			return fmt.Errorf("rule %s: %w", rule.Name, err)
		}

		// Compile the expression
		program, err := filter.CompileExpression(rule.Expression, recordType)
		if err != nil {
			return fmt.Errorf("failed to compile rule %s: %w", rule.Name, err)
		}

		config.Rules[i].compiled = program
	}

	return nil
}

// parseRecordType converts a type string (e.g., "TCP", "HTTP") to types.Type.
func parseRecordType(typeStr string) (types.Type, error) {
	// Add NC_ prefix if not present
	if !strings.HasPrefix(typeStr, "NC_") {
		typeStr = "NC_" + typeStr
	}

	// Look up the type value
	typeValue, ok := types.Type_value[typeStr]
	if !ok {
		return 0, fmt.Errorf("unknown record type: %s", typeStr)
	}

	return types.Type(typeValue), nil
}

// ValidateAction checks if an action string is valid.
func ValidateAction(action Action) bool {
	switch action {
	case ActionAccept, ActionDrop, ActionModifyPayload, ActionInjectPacket,
		ActionInjectTCPRST, ActionInjectDNS, ActionInjectARP, ActionDelay,
		ActionHTTPInjectHeader, ActionHTTPSSLStrip, ActionHTTPRedirect:
		return true
	default:
		return false
	}
}

// Validate validates the rule configuration.
func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if r.Type == "" {
		return fmt.Errorf("rule type is required")
	}

	if r.Expression == "" {
		return fmt.Errorf("rule expression is required")
	}

	if !ValidateAction(r.Action) {
		return fmt.Errorf("invalid action: %s", r.Action)
	}

	return nil
}

// IsCompiled returns true if the rule has been compiled.
func (r *Rule) IsCompiled() bool {
	return r.compiled != nil
}

// GetCompiled returns the compiled expression program.
func (r *Rule) GetCompiled() *vm.Program {
	return r.compiled
}
