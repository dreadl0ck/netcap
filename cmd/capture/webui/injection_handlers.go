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

package webui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/injection"
)

// InjectionRuleResponse represents an injection rule for the API
type InjectionRuleResponse struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"`
	Expression   string                 `json:"expression"`
	Action       string                 `json:"action"`
	ActionConfig map[string]interface{} `json:"actionConfig,omitempty"`
	Enabled      bool                   `json:"enabled"`
	Priority     int                    `json:"priority"`
	StopOnMatch  bool                   `json:"stopOnMatch"`
	Tags         []string               `json:"tags"`
}

// InjectionRulesResponse represents the response containing all injection rules
type InjectionRulesResponse struct {
	Rules       []InjectionRuleResponse `json:"rules"`
	Description string                  `json:"description"`
}

// CreateInjectionRuleRequest represents a request to create a new injection rule
type CreateInjectionRuleRequest struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"`
	Expression   string                 `json:"expression"`
	Action       string                 `json:"action"`
	ActionConfig map[string]interface{} `json:"actionConfig,omitempty"`
	Enabled      bool                   `json:"enabled"`
	Priority     int                    `json:"priority,omitempty"`
	StopOnMatch  bool                   `json:"stopOnMatch,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
}

// UpdateInjectionRuleRequest represents a request to update an injection rule
type UpdateInjectionRuleRequest struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"`
	Expression   string                 `json:"expression"`
	Action       string                 `json:"action"`
	ActionConfig map[string]interface{} `json:"actionConfig,omitempty"`
	Enabled      bool                   `json:"enabled"`
	Priority     int                    `json:"priority,omitempty"`
	StopOnMatch  bool                   `json:"stopOnMatch,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
}

// InjectionEvent represents an event when an injection rule is triggered
type InjectionEvent struct {
	ID          string                 `json:"id"`
	Timestamp   int64                  `json:"timestamp"`
	RuleName    string                 `json:"ruleName"`
	RuleAction  string                 `json:"ruleAction"`
	RecordType  string                 `json:"recordType"`
	SrcIP       string                 `json:"srcIP,omitempty"`
	DstIP       string                 `json:"dstIP,omitempty"`
	SrcPort     int                    `json:"srcPort,omitempty"`
	DstPort     int                    `json:"dstPort,omitempty"`
	Result      string                 `json:"result"` // "success", "failed", "skipped"
	Error       string                 `json:"error,omitempty"`
	ActionData  map[string]interface{} `json:"actionData,omitempty"`
}

// InjectionEventsResponse represents the response containing injection events
type InjectionEventsResponse struct {
	Events     []InjectionEvent `json:"events"`
	TotalCount int              `json:"totalCount"`
}

// InjectionStatsResponse represents statistics about injection rules and events
type InjectionStatsResponse struct {
	TotalRules     int            `json:"totalRules"`
	EnabledRules   int            `json:"enabledRules"`
	TotalEvents    int            `json:"totalEvents"`
	EventsByRule   map[string]int `json:"eventsByRule"`
	EventsByResult map[string]int `json:"eventsByResult"`
	EventsByAction map[string]int `json:"eventsByAction"`
	LastEventTime  int64          `json:"lastEventTime,omitempty"`
}

// Injection events storage (in-memory for now)
var (
	injectionEvents      []InjectionEvent
	injectionEventsMutex sync.RWMutex
	injectionEventID     int64
)

// injectionRulesConfig is the cached injection rules configuration
var (
	injectionRulesConfig      *injection.Config
	injectionRulesConfigMutex sync.RWMutex
)

// getInjectionRulesFolderPath returns the path to the injection rules folder
func (s *Server) getInjectionRulesFolderPath() string {
	s.mu.RLock()
	isServiceMode := s.isServiceMode
	serviceConfig := s.serviceConfig
	outDir := s.outDir
	s.mu.RUnlock()

	// In service mode, use the service data directory
	if isServiceMode && serviceConfig != nil {
		return filepath.Join(serviceConfig.DataDir, "injection-rules")
	}

	// In local mode, get parent directory of output directory
	parentDir := filepath.Dir(outDir)
	return filepath.Join(parentDir, "injection-rules")
}

// loadInjectionRulesConfig loads injection rules from the configs directory
func (s *Server) loadInjectionRulesConfig() (*injection.Config, error) {
	// Check cache first
	injectionRulesConfigMutex.RLock()
	if injectionRulesConfig != nil {
		cached := injectionRulesConfig
		injectionRulesConfigMutex.RUnlock()
		return cached, nil
	}
	injectionRulesConfigMutex.RUnlock()

	// Initialize empty config
	config := &injection.Config{Rules: []*injection.Rule{}}

	// Try to load from configs/injection-rules.yml in project root
	// First check the configs directory relative to output dir
	configPaths := []string{
		filepath.Join(s.getInjectionRulesFolderPath(), "injection-rules.yml"),
	}

	// Also check for system-wide config
	homeDir, err := os.UserHomeDir()
	if err == nil {
		configPaths = append(configPaths, filepath.Join(homeDir, ".config", "netcap", "injection-rules.yml"))
	}

	// Check for config in the repository's configs directory
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		configPaths = append(configPaths, 
			filepath.Join(execDir, "configs", "injection-rules.yml"),
			filepath.Join(execDir, "..", "configs", "injection-rules.yml"),
		)
	}

	// Try working directory
	cwd, err := os.Getwd()
	if err == nil {
		configPaths = append(configPaths, filepath.Join(cwd, "configs", "injection-rules.yml"))
	}

	// Load from the first available path
	for _, configPath := range configPaths {
		if _, err := os.Stat(configPath); err == nil {
			fileConfig, err := injection.LoadRulesFromFile(configPath)
			if err != nil {
				log.Printf("[WebUI] Warning: failed to load injection rules from %s: %v", configPath, err)
				continue
			}
			config = fileConfig
			log.Printf("[WebUI] Loaded %d injection rules from %s", len(config.Rules), configPath)
			break
		}
	}

	// Also load from injection rules folder if it exists
	rulesFolder := s.getInjectionRulesFolderPath()
	if _, err := os.Stat(rulesFolder); err == nil {
		entries, err := os.ReadDir(rulesFolder)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
					continue
				}

				filePath := filepath.Join(rulesFolder, entry.Name())
				fileConfig, err := injection.LoadRulesFromFile(filePath)
				if err != nil {
					log.Printf("[WebUI] Warning: failed to load injection rules from %s: %v", entry.Name(), err)
					continue
				}

				config.Rules = append(config.Rules, fileConfig.Rules...)
				log.Printf("[WebUI] Loaded %d injection rules from %s", len(fileConfig.Rules), entry.Name())
			}
		}
	}

	log.Printf("[WebUI] Total injection rules loaded: %d", len(config.Rules))

	// Cache the config
	injectionRulesConfigMutex.Lock()
	injectionRulesConfig = config
	injectionRulesConfigMutex.Unlock()

	return config, nil
}

// invalidateInjectionRulesCache clears the cached injection rules configuration
func (s *Server) invalidateInjectionRulesCache() {
	injectionRulesConfigMutex.Lock()
	injectionRulesConfig = nil
	injectionRulesConfigMutex.Unlock()
	log.Printf("[WebUI] Injection rules cache invalidated")
}

// saveInjectionRulesConfig saves injection rules to the rules folder
func (s *Server) saveInjectionRulesConfig(config *injection.Config) error {
	rulesFolder := s.getInjectionRulesFolderPath()

	log.Printf("[WebUI] saveInjectionRulesConfig: using rules folder path: %s", rulesFolder)

	// Create rules folder if it doesn't exist
	if err := os.MkdirAll(rulesFolder, 0755); err != nil {
		return fmt.Errorf("failed to create injection rules folder: %w", err)
	}

	// Save all rules to a single file
	filePath := filepath.Join(rulesFolder, "custom-rules.yml")

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal injection rules: %w", err)
	}

	log.Printf("[WebUI] Writing %d injection rules to %s", len(config.Rules), filePath)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write injection rules file: %w", err)
	}

	// Invalidate cache after successful save
	s.invalidateInjectionRulesCache()

	return nil
}

// handleInjectionRules handles GET (list all rules) and POST (create new rule) requests
func (s *Server) handleInjectionRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetInjectionRules(w, r)
	case http.MethodPost:
		s.handleCreateInjectionRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetInjectionRules returns all injection rules
func (s *Server) handleGetInjectionRules(w http.ResponseWriter, r *http.Request) {
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	// Convert to response format
	response := InjectionRulesResponse{
		Rules:       make([]InjectionRuleResponse, 0, len(config.Rules)),
		Description: config.Description,
	}

	for _, rule := range config.Rules {
		tags := rule.Tags
		if tags == nil {
			tags = []string{}
		}

		response.Rules = append(response.Rules, InjectionRuleResponse{
			ID:           rule.Name,
			Name:         rule.Name,
			Description:  rule.Description,
			Type:         rule.Type,
			Expression:   rule.Expression,
			Action:       string(rule.Action),
			ActionConfig: rule.ActionConfig,
			Enabled:      rule.Enabled,
			Priority:     rule.Priority,
			StopOnMatch:  rule.StopOnMatch,
			Tags:         tags,
		})
	}

	RespondJSON(w, http.StatusOK, response)
}

// handleCreateInjectionRule creates a new injection rule
func (s *Server) handleCreateInjectionRule(w http.ResponseWriter, r *http.Request) {
	var req CreateInjectionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid request body",
		})
		return
	}

	// Validate required fields
	if req.Name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule name is required",
		})
		return
	}

	if req.Type == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule type is required",
		})
		return
	}

	if req.Expression == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule expression is required",
		})
		return
	}

	if req.Action == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule action is required",
		})
		return
	}

	// Validate action
	if !injection.ValidateAction(injection.Action(req.Action)) {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("Invalid action: %s", req.Action),
		})
		return
	}

	// Load existing config
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	// Check if rule with same name already exists
	for _, rule := range config.Rules {
		if rule.Name == req.Name {
			RespondJSON(w, http.StatusConflict, map[string]interface{}{
				"error": "An injection rule with this name already exists",
			})
			return
		}
	}

	// Create new rule
	newRule := &injection.Rule{
		Name:         req.Name,
		Description:  req.Description,
		Type:         req.Type,
		Expression:   req.Expression,
		Action:       injection.Action(req.Action),
		ActionConfig: req.ActionConfig,
		Enabled:      req.Enabled,
		Priority:     req.Priority,
		StopOnMatch:  req.StopOnMatch,
		Tags:         req.Tags,
	}

	// Add to config
	config.Rules = append(config.Rules, newRule)

	// Save config
	if err := s.saveInjectionRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to save injection rules: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Created new injection rule: %s", req.Name)

	RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Injection rule created successfully",
		"rule": InjectionRuleResponse{
			ID:           newRule.Name,
			Name:         newRule.Name,
			Description:  newRule.Description,
			Type:         newRule.Type,
			Expression:   newRule.Expression,
			Action:       string(newRule.Action),
			ActionConfig: newRule.ActionConfig,
			Enabled:      newRule.Enabled,
			Priority:     newRule.Priority,
			StopOnMatch:  newRule.StopOnMatch,
			Tags:         newRule.Tags,
		},
	})
}

// ToggleInjectionRuleRequest represents a request to toggle a rule's enabled state
type ToggleInjectionRuleRequest struct {
	Enabled bool `json:"enabled"`
}

// handleInjectionRule handles GET (get specific rule), PUT (update rule), PATCH (toggle), and DELETE (delete rule) requests
func (s *Server) handleInjectionRule(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from URL path: /api/injection-rules/{id}
	encodedRuleID := strings.TrimPrefix(r.URL.Path, "/api/injection-rules/")
	if encodedRuleID == "" || encodedRuleID == "/api/injection-rules" {
		http.Error(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	// URL-decode the rule ID
	ruleID, err := url.PathUnescape(encodedRuleID)
	if err != nil {
		http.Error(w, "Invalid rule ID encoding", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetInjectionRule(w, r, ruleID)
	case http.MethodPut:
		s.handleUpdateInjectionRule(w, r, ruleID)
	case http.MethodPatch:
		s.handleToggleInjectionRule(w, r, ruleID)
	case http.MethodDelete:
		s.handleDeleteInjectionRule(w, r, ruleID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetInjectionRule returns a specific injection rule
func (s *Server) handleGetInjectionRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	// Find the rule
	for _, rule := range config.Rules {
		if rule.Name == ruleID {
			tags := rule.Tags
			if tags == nil {
				tags = []string{}
			}

			RespondJSON(w, http.StatusOK, InjectionRuleResponse{
				ID:           rule.Name,
				Name:         rule.Name,
				Description:  rule.Description,
				Type:         rule.Type,
				Expression:   rule.Expression,
				Action:       string(rule.Action),
				ActionConfig: rule.ActionConfig,
				Enabled:      rule.Enabled,
				Priority:     rule.Priority,
				StopOnMatch:  rule.StopOnMatch,
				Tags:         tags,
			})
			return
		}
	}

	RespondJSON(w, http.StatusNotFound, map[string]interface{}{
		"error": "Injection rule not found",
	})
}

// handleUpdateInjectionRule updates an existing injection rule
func (s *Server) handleUpdateInjectionRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req UpdateInjectionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid request body",
		})
		return
	}

	// Validate required fields
	if req.Name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule name is required",
		})
		return
	}

	if req.Type == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule type is required",
		})
		return
	}

	if req.Expression == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule expression is required",
		})
		return
	}

	if req.Action == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Rule action is required",
		})
		return
	}

	// Validate action
	if !injection.ValidateAction(injection.Action(req.Action)) {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("Invalid action: %s", req.Action),
		})
		return
	}

	// Load existing config
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	// Find and update the rule
	found := false
	for i, rule := range config.Rules {
		if rule.Name == ruleID {
			// If name is being changed, check for conflicts
			if req.Name != ruleID {
				for _, r := range config.Rules {
					if r.Name == req.Name {
						RespondJSON(w, http.StatusConflict, map[string]interface{}{
							"error": "An injection rule with this name already exists",
						})
						return
					}
				}
			}

			config.Rules[i].Name = req.Name
			config.Rules[i].Description = req.Description
			config.Rules[i].Type = req.Type
			config.Rules[i].Expression = req.Expression
			config.Rules[i].Action = injection.Action(req.Action)
			config.Rules[i].ActionConfig = req.ActionConfig
			config.Rules[i].Enabled = req.Enabled
			config.Rules[i].Priority = req.Priority
			config.Rules[i].StopOnMatch = req.StopOnMatch
			config.Rules[i].Tags = req.Tags
			found = true
			break
		}
	}

	if !found {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Injection rule not found",
		})
		return
	}

	// Save config
	if err := s.saveInjectionRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to save injection rules: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Updated injection rule: %s -> %s", ruleID, req.Name)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Injection rule updated successfully",
	})
}

// handleDeleteInjectionRule deletes an injection rule
func (s *Server) handleDeleteInjectionRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	// Load existing config
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	// Find and remove the rule
	found := false
	newRules := make([]*injection.Rule, 0, len(config.Rules))
	for _, rule := range config.Rules {
		if rule.Name == ruleID {
			found = true
			continue
		}
		newRules = append(newRules, rule)
	}

	if !found {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Injection rule not found",
		})
		return
	}

	config.Rules = newRules

	// Save config
	if err := s.saveInjectionRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to save injection rules: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Deleted injection rule: %s", ruleID)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Injection rule deleted successfully",
	})
}

// handleToggleInjectionRule toggles an injection rule's enabled state
func (s *Server) handleToggleInjectionRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req ToggleInjectionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid request body",
		})
		return
	}

	// Load existing config
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	// Find and toggle the rule
	found := false
	for i, rule := range config.Rules {
		if rule.Name == ruleID {
			config.Rules[i].Enabled = req.Enabled
			found = true
			break
		}
	}

	if !found {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Injection rule not found",
		})
		return
	}

	// Save config
	if err := s.saveInjectionRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to save injection rules: %v", err),
		})
		return
	}

	status := "disabled"
	if req.Enabled {
		status = "enabled"
	}
	log.Printf("[WebUI] Toggled injection rule %s: %s", ruleID, status)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Injection rule %s", status),
		"enabled": req.Enabled,
	})
}

// handleInjectionEvents handles GET requests for injection events
func (s *Server) handleInjectionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get filter parameters
	filterRule := r.URL.Query().Get("rule")
	filterResult := r.URL.Query().Get("result")
	filterAction := r.URL.Query().Get("action")

	injectionEventsMutex.RLock()
	events := make([]InjectionEvent, 0, len(injectionEvents))
	for _, event := range injectionEvents {
		// Apply filters
		if filterRule != "" && event.RuleName != filterRule {
			continue
		}
		if filterResult != "" && event.Result != filterResult {
			continue
		}
		if filterAction != "" && event.RuleAction != filterAction {
			continue
		}
		events = append(events, event)
	}
	totalCount := len(injectionEvents)
	injectionEventsMutex.RUnlock()

	// Reverse to show newest first
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	RespondJSON(w, http.StatusOK, InjectionEventsResponse{
		Events:     events,
		TotalCount: totalCount,
	})
}

// handleInjectionEventsManage handles DELETE (clear) requests for injection events
func (s *Server) handleInjectionEventsManage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	injectionEventsMutex.Lock()
	clearedCount := len(injectionEvents)
	injectionEvents = []InjectionEvent{}
	injectionEventsMutex.Unlock()

	log.Printf("[WebUI] Cleared %d injection events", clearedCount)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Cleared %d injection events", clearedCount),
	})
}

// handleInjectionStats returns statistics about injection rules and events
func (s *Server) handleInjectionStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get rules stats
	config, err := s.loadInjectionRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load injection rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load injection rules: %v", err),
		})
		return
	}

	enabledCount := 0
	for _, rule := range config.Rules {
		if rule.Enabled {
			enabledCount++
		}
	}

	// Get events stats
	injectionEventsMutex.RLock()
	totalEvents := len(injectionEvents)
	eventsByRule := make(map[string]int)
	eventsByResult := make(map[string]int)
	eventsByAction := make(map[string]int)
	var lastEventTime int64

	for _, event := range injectionEvents {
		eventsByRule[event.RuleName]++
		eventsByResult[event.Result]++
		eventsByAction[event.RuleAction]++
		if event.Timestamp > lastEventTime {
			lastEventTime = event.Timestamp
		}
	}
	injectionEventsMutex.RUnlock()

	RespondJSON(w, http.StatusOK, InjectionStatsResponse{
		TotalRules:     len(config.Rules),
		EnabledRules:   enabledCount,
		TotalEvents:    totalEvents,
		EventsByRule:   eventsByRule,
		EventsByResult: eventsByResult,
		EventsByAction: eventsByAction,
		LastEventTime:  lastEventTime,
	})
}

// RecordInjectionEvent records an injection event (called from the injection engine)
func RecordInjectionEvent(ruleName, ruleAction, recordType, srcIP, dstIP string, srcPort, dstPort int, result string, err error, actionData map[string]interface{}) {
	injectionEventsMutex.Lock()
	defer injectionEventsMutex.Unlock()

	injectionEventID++
	event := InjectionEvent{
		ID:         fmt.Sprintf("event-%d", injectionEventID),
		Timestamp:  time.Now().UnixNano(),
		RuleName:   ruleName,
		RuleAction: ruleAction,
		RecordType: recordType,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Result:     result,
		ActionData: actionData,
	}

	if err != nil {
		event.Error = err.Error()
	}

	// Keep only last 1000 events
	if len(injectionEvents) >= 1000 {
		injectionEvents = injectionEvents[1:]
	}
	injectionEvents = append(injectionEvents, event)
}

// GetAvailableActions returns list of available injection actions
func (s *Server) handleInjectionActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actions := []map[string]interface{}{
		{
			"value":       "accept",
			"label":       "Accept",
			"description": "Forward the packet unchanged",
			"category":    "basic",
		},
		{
			"value":       "drop",
			"label":       "Drop",
			"description": "Silently drop the packet",
			"category":    "basic",
		},
		{
			"value":       "delay",
			"label":       "Delay",
			"description": "Delay packet forwarding by a specified duration",
			"category":    "basic",
			"configFields": []map[string]string{
				{"name": "delay_ms", "type": "number", "label": "Delay (ms)", "required": "true"},
			},
		},
		{
			"value":       "inject_tcp_rst",
			"label":       "Inject TCP RST",
			"description": "Send a TCP RST to terminate the connection",
			"category":    "injection",
		},
		{
			"value":       "inject_dns",
			"label":       "Inject DNS Response",
			"description": "Spoof a DNS response",
			"category":    "injection",
			"configFields": []map[string]string{
				{"name": "response_ip", "type": "text", "label": "Response IP", "required": "true"},
				{"name": "ttl", "type": "number", "label": "TTL", "required": "false"},
			},
		},
		{
			"value":       "inject_arp",
			"label":       "Inject ARP Reply",
			"description": "Send a spoofed ARP reply",
			"category":    "injection",
			"configFields": []map[string]string{
				{"name": "spoof_mac", "type": "text", "label": "Spoof MAC", "required": "true"},
			},
		},
		{
			"value":       "modify_payload",
			"label":       "Modify Payload",
			"description": "Modify the packet payload using search/replace",
			"category":    "modification",
			"configFields": []map[string]string{
				{"name": "search", "type": "text", "label": "Search", "required": "true"},
				{"name": "replace", "type": "text", "label": "Replace", "required": "true"},
			},
		},
		{
			"value":       "http_inject_header",
			"label":       "HTTP Inject Header",
			"description": "Inject or modify HTTP headers",
			"category":    "http",
			"configFields": []map[string]string{
				{"name": "header_name", "type": "text", "label": "Header Name", "required": "true"},
				{"name": "header_value", "type": "text", "label": "Header Value", "required": "true"},
			},
		},
		{
			"value":       "http_redirect",
			"label":       "HTTP Redirect",
			"description": "Inject an HTTP redirect response",
			"category":    "http",
			"configFields": []map[string]string{
				{"name": "redirect_url", "type": "text", "label": "Redirect URL", "required": "true"},
				{"name": "status_code", "type": "number", "label": "Status Code", "required": "false"},
			},
		},
		{
			"value":       "http_ssl_strip",
			"label":       "HTTP SSL Strip",
			"description": "Downgrade HTTPS links to HTTP in responses",
			"category":    "http",
		},
		{
			"value":       "iptables_block",
			"label":       "IPTables Block",
			"description": "Block an IP/CIDR using iptables DROP",
			"category":    "firewall",
			"configFields": []map[string]string{
				{"name": "target", "type": "select", "label": "Target", "options": "source,destination", "required": "true"},
				{"name": "duration", "type": "text", "label": "Duration", "required": "false"},
				{"name": "rule_name", "type": "text", "label": "Rule Name", "required": "false"},
			},
		},
		{
			"value":       "iptables_reject",
			"label":       "IPTables Reject",
			"description": "Reject traffic with ICMP response",
			"category":    "firewall",
			"configFields": []map[string]string{
				{"name": "target", "type": "select", "label": "Target", "options": "source,destination", "required": "true"},
				{"name": "duration", "type": "text", "label": "Duration", "required": "false"},
			},
		},
		{
			"value":       "iptables_rate_limit",
			"label":       "IPTables Rate Limit",
			"description": "Rate-limit traffic from/to an IP",
			"category":    "firewall",
			"configFields": []map[string]string{
				{"name": "target", "type": "select", "label": "Target", "options": "source,destination", "required": "true"},
				{"name": "rate", "type": "text", "label": "Rate (e.g., 10/minute)", "required": "true"},
				{"name": "burst", "type": "number", "label": "Burst", "required": "false"},
			},
		},
		{
			"value":       "iptables_log",
			"label":       "IPTables Log",
			"description": "Log matching traffic via iptables LOG target",
			"category":    "firewall",
			"configFields": []map[string]string{
				{"name": "prefix", "type": "text", "label": "Log Prefix", "required": "false"},
			},
		},
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"actions": actions,
	})
}

