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

package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/rules"
	"github.com/dreadl0ck/netcap/types"
)

// ResponseActionAPI represents a response action for the API
type ResponseActionAPI struct {
	Type    string         `json:"type"`
	Config  map[string]any `json:"config,omitempty"`
	Enabled *bool          `json:"enabled,omitempty"`
}

// RuleResponse represents a rule for the API
type RuleResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Type              string   `json:"type"`
	Expression        string   `json:"expression"`
	Severity          string   `json:"severity"`
	MITRE             []string `json:"mitre"`
	Tags              []string `json:"tags"`
	Enabled           bool     `json:"enabled"`
	Threshold         int      `json:"threshold,omitempty"`
	ThresholdWindow   int      `json:"thresholdWindow,omitempty"`
	DistinctField     string   `json:"distinctField,omitempty"`
	DistinctThreshold int      `json:"distinctThreshold,omitempty"`
	// Sequence is read-only here: the UI cannot author an ordered correlation
	// gate, but a gated rule must not be displayed as an ungated one.
	Sequence *rules.Sequence     `json:"sequence,omitempty"`
	Actions  []ResponseActionAPI `json:"actions,omitempty"`
}

// RulesConfigResponse represents the full rules configuration
type RulesConfigResponse struct {
	Rules []RuleResponse `json:"rules"`
}

// CreateRuleRequest represents a request to create a new rule
type CreateRuleRequest struct {
	Name              string              `json:"name"`
	Description       string              `json:"description"`
	Type              string              `json:"type"`
	Expression        string              `json:"expression"`
	Severity          string              `json:"severity"`
	MITRE             []string            `json:"mitre"`
	Tags              []string            `json:"tags"`
	Enabled           bool                `json:"enabled"`
	Threshold         int                 `json:"threshold,omitempty"`
	ThresholdWindow   int                 `json:"thresholdWindow,omitempty"`
	DistinctField     string              `json:"distinctField,omitempty"`
	DistinctThreshold int                 `json:"distinctThreshold,omitempty"`
	Actions           []ResponseActionAPI `json:"actions,omitempty"`
}

// UpdateRuleRequest represents a request to update a rule
type UpdateRuleRequest struct {
	Name              string              `json:"name"`
	Description       string              `json:"description"`
	Type              string              `json:"type"`
	Expression        string              `json:"expression"`
	Severity          string              `json:"severity"`
	MITRE             []string            `json:"mitre"`
	Tags              []string            `json:"tags"`
	Enabled           bool                `json:"enabled"`
	Threshold         int                 `json:"threshold,omitempty"`
	ThresholdWindow   int                 `json:"thresholdWindow,omitempty"`
	DistinctField     string              `json:"distinctField,omitempty"`
	DistinctThreshold int                 `json:"distinctThreshold,omitempty"`
	Actions           []ResponseActionAPI `json:"actions,omitempty"`
}

// RuleSetInfo represents information about a rule set (YAML file)
type RuleSetInfo struct {
	Name         string `json:"name"`         // Filename without .yml extension
	Filename     string `json:"filename"`     // Full filename with extension
	RuleCount    int    `json:"ruleCount"`    // Number of rules in this set
	Enabled      bool   `json:"enabled"`      // Whether the rule set is enabled
	Description  string `json:"description"`  // Optional description from first rule or filename
	IsEmbedded   bool   `json:"isEmbedded"`   // Whether this is an embedded default rule set
	IsOverridden bool   `json:"isOverridden"` // Whether this embedded rule set has been overridden by a file
}

// RuleSetsResponse represents the response with all rule sets
type RuleSetsResponse struct {
	RuleSets []RuleSetInfo `json:"ruleSets"`
}

// UpdateRuleSetRequest represents a request to enable/disable a rule set
type UpdateRuleSetRequest struct {
	Enabled bool `json:"enabled"`
}

// convertActionsToAPI converts rules.ResponseAction slice to API format
func convertActionsToAPI(actions []*rules.ResponseAction) []ResponseActionAPI {
	if actions == nil {
		return nil
	}
	result := make([]ResponseActionAPI, len(actions))
	for i, action := range actions {
		result[i] = ResponseActionAPI{
			Type:    action.Type,
			Config:  action.Config,
			Enabled: action.Enabled,
		}
	}
	return result
}

// convertActionsFromAPI converts API format to rules.ResponseAction slice
func convertActionsFromAPI(actions []ResponseActionAPI) []*rules.ResponseAction {
	if actions == nil {
		return nil
	}
	result := make([]*rules.ResponseAction, len(actions))
	for i, action := range actions {
		result[i] = &rules.ResponseAction{
			Type:    action.Type,
			Config:  action.Config,
			Enabled: action.Enabled,
		}
	}
	return result
}

// getRulesFolderPath returns the path to the rules folder
// In service mode: uses service data directory
// In local mode: uses parent directory of output directory (in same dir as pcaps)
func (s *Server) getRulesFolderPath() string {
	s.mu.RLock()
	isServiceMode := s.isServiceMode
	serviceConfig := s.serviceConfig
	outDir := s.outDir
	s.mu.RUnlock()

	// In service mode, use the service data directory
	if isServiceMode && serviceConfig != nil {
		return filepath.Join(serviceConfig.DataDir, "rules")
	}

	// In local mode, get parent directory of output directory
	parentDir := filepath.Dir(outDir)
	return filepath.Join(parentDir, "rules")
}

// loadRulesConfig loads the rules configuration.
// It first loads embedded default rules, then merges any file-based overrides.
// Note: This tracks which file each rule came from for rule set management
func (s *Server) loadRulesConfig() (*rules.Config, error) {
	// Check cache first
	s.rulesConfigMutex.RLock()
	if s.rulesConfig != nil {
		cached := s.rulesConfig.(*rules.Config)
		s.rulesConfigMutex.RUnlock()
		return cached, nil
	}
	s.rulesConfigMutex.RUnlock()

	// Start with embedded default rules
	config, err := rules.LoadEmbeddedRules()
	if err != nil {
		log.Printf("[WebUI] Warning: failed to load embedded detection rules: %v", err)
		config = &rules.Config{Rules: []*rules.Rule{}}
	} else {
		log.Printf("[WebUI] Loaded %d embedded default detection rules", len(config.Rules))
	}

	// Load additional/override rules from the rules folder
	rulesFolder := s.getRulesFolderPath()
	if _, err := os.Stat(rulesFolder); err == nil {
		entries, err := os.ReadDir(rulesFolder)
		if err != nil {
			log.Printf("[WebUI] Warning: failed to read rules folder: %v", err)
		} else {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
					continue
				}

				filePath := filepath.Join(rulesFolder, entry.Name())
				data, err := os.ReadFile(filePath)
				if err != nil {
					log.Printf("[WebUI] Warning: failed to read rules file %s: %v", entry.Name(), err)
					continue
				}

				var fileConfig rules.Config
				if err := yaml.Unmarshal(data, &fileConfig); err != nil {
					log.Printf("[WebUI] Warning: failed to parse rules file %s: %v", entry.Name(), err)
					continue
				}

				// Tag each rule with its source file (used for rule set management)
				for _, rule := range fileConfig.Rules {
					if rule.Tags == nil {
						rule.Tags = []string{}
					}
					// Add a special tag to track the rule set
					ruleSetTag := "ruleset:" + strings.TrimSuffix(entry.Name(), ".yml")
					// Check if tag already exists
					hasTag := slices.Contains(rule.Tags, ruleSetTag)
					if !hasTag {
						rule.Tags = append(rule.Tags, ruleSetTag)
					}
				}

				// Merge file rules with existing config (file rules override embedded by name)
				config = rules.MergeConfigs(config, &fileConfig)
				log.Printf("[WebUI] Merged %d rules from %s (overrides embedded)", len(fileConfig.Rules), entry.Name())
			}
		}
	} else {
		log.Printf("[WebUI] Rules folder not found at %s, creating it", rulesFolder)
		// Create the rules folder if it doesn't exist
		if err := os.MkdirAll(rulesFolder, 0755); err != nil {
			return nil, fmt.Errorf("failed to create rules folder: %w", err)
		}
	}

	log.Printf("[WebUI] Total rules loaded: %d", len(config.Rules))

	// Cache the config
	s.rulesConfigMutex.Lock()
	s.rulesConfig = config
	s.rulesConfigMutex.Unlock()

	return config, nil
}

// invalidateRulesCache clears the cached rules configuration
func (s *Server) invalidateRulesCache() {
	s.rulesConfigMutex.Lock()
	s.rulesConfig = nil
	s.rulesConfigMutex.Unlock()
	log.Printf("[WebUI] Rules cache invalidated")
}

// saveRulesConfig saves all rules back to their original rule set files
// Rules are grouped by their ruleset tag and saved to the corresponding file
func (s *Server) saveRulesConfig(config *rules.Config) error {
	rulesFolder := s.getRulesFolderPath()

	log.Printf("[WebUI] saveRulesConfig: using rules folder path: %s", rulesFolder)

	// Create rules folder if it doesn't exist
	if err := os.MkdirAll(rulesFolder, 0755); err != nil {
		return fmt.Errorf("failed to create rules folder: %w", err)
	}

	// Group rules by their rule set (from the ruleset: tag)
	ruleSetMap := make(map[string][]*rules.Rule)
	var orphanedRules []*rules.Rule

	for _, rule := range config.Rules {
		// Find the ruleset tag
		ruleSetName := ""
		for _, tag := range rule.Tags {
			if after, ok := strings.CutPrefix(tag, "ruleset:"); ok {
				ruleSetName = after
				break
			}
		}

		if ruleSetName != "" {
			ruleSetMap[ruleSetName] = append(ruleSetMap[ruleSetName], rule)
		} else {
			// Rules without a ruleset tag are orphaned (created via UI)
			orphanedRules = append(orphanedRules, rule)
		}
	}

	log.Printf("[WebUI] saveRulesConfig: grouped %d rules into %d rule sets", len(config.Rules), len(ruleSetMap))

	// Save each rule set to its original file
	savedFiles := make(map[string]bool)
	for ruleSetName, rulesList := range ruleSetMap {
		filename := ruleSetName + ".yml"
		filePath := filepath.Join(rulesFolder, filename)

		// Try to load the original file to preserve the description
		var originalDescription string
		if originalData, err := os.ReadFile(filePath); err == nil {
			var originalConfig rules.Config
			if err := yaml.Unmarshal(originalData, &originalConfig); err == nil {
				originalDescription = originalConfig.Description
			}
		}

		// Remove the ruleset tag from each rule before saving (it will be re-added on load)
		rulesForSave := make([]*rules.Rule, len(rulesList))
		for i, rule := range rulesList {
			// Create a copy of the rule
			ruleCopy := rules.Rule{
				Name:              rule.Name,
				Description:       rule.Description,
				Type:              rule.Type,
				Expression:        rule.Expression,
				Severity:          rule.Severity,
				MITRE:             rule.MITRE,
				Enabled:           rule.Enabled,
				Threshold:         rule.Threshold,
				ThresholdWindow:   rule.ThresholdWindow,
				DistinctField:     rule.DistinctField,
				DistinctThreshold: rule.DistinctThreshold,
				Sequence:          rule.Sequence,
				Actions:           rule.Actions,
			}
			// Filter out the ruleset tag
			newTags := make([]string, 0, len(rule.Tags))
			for _, tag := range rule.Tags {
				if !strings.HasPrefix(tag, "ruleset:") {
					newTags = append(newTags, tag)
				}
			}
			ruleCopy.Tags = newTags
			rulesForSave[i] = &ruleCopy
		}

		ruleSetConfig := &rules.Config{
			Description: originalDescription,
			Rules:       rulesForSave,
		}

		data, err := yaml.Marshal(ruleSetConfig)
		if err != nil {
			log.Printf("[WebUI] ERROR: failed to marshal rule set %s: %v", ruleSetName, err)
			continue
		}

		log.Printf("[WebUI] Writing %d rules to %s", len(rulesList), filePath)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			log.Printf("[WebUI] ERROR: failed to write rule set file %s: %v", filename, err)
			continue
		}

		savedFiles[filename] = true
		log.Printf("[WebUI] Successfully saved %d rules to rule set file: %s", len(rulesList), filename)
	}

	// Save orphaned rules as individual files (these were created via the UI)
	for _, rule := range orphanedRules {
		// Create a copy of the rule without ruleset tags
		ruleCopy := rules.Rule{
			Name:              rule.Name,
			Description:       rule.Description,
			Type:              rule.Type,
			Expression:        rule.Expression,
			Severity:          rule.Severity,
			MITRE:             rule.MITRE,
			Enabled:           rule.Enabled,
			Threshold:         rule.Threshold,
			ThresholdWindow:   rule.ThresholdWindow,
			DistinctField:     rule.DistinctField,
			DistinctThreshold: rule.DistinctThreshold,
			Sequence:          rule.Sequence,
			Actions:           rule.Actions,
		}

		// Filter out the ruleset tag
		newTags := make([]string, 0, len(rule.Tags))
		for _, tag := range rule.Tags {
			if !strings.HasPrefix(tag, "ruleset:") {
				newTags = append(newTags, tag)
			}
		}
		ruleCopy.Tags = newTags

		ruleConfig := &rules.Config{
			Rules: []*rules.Rule{&ruleCopy},
		}

		data, err := yaml.Marshal(ruleConfig)
		if err != nil {
			log.Printf("[WebUI] Warning: failed to marshal orphaned rule %s: %v", rule.Name, err)
			continue
		}

		filename := sanitizeFilename(rule.Name) + ".yml"
		filePath := filepath.Join(rulesFolder, filename)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			log.Printf("[WebUI] Warning: failed to write orphaned rule file %s: %v", filename, err)
			continue
		}

		savedFiles[filename] = true
		log.Printf("[WebUI] Saved orphaned rule to file: %s", filename)
	}

	// Note: We don't delete existing files to avoid data loss
	// Users can manually delete old rule files if needed

	// Invalidate cache after successful save
	s.invalidateRulesCache()

	return nil
}

// sanitizeFilename converts a rule name to a safe filename
func sanitizeFilename(name string) string {
	// Replace any characters that are not alphanumeric, dash, or underscore
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)

	// Ensure it's not empty
	if safe == "" {
		safe = "rule"
	}

	return safe
}

// handleRules handles GET (list all rules) and POST (create new rule) requests
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetRules(w, r)
	case http.MethodPost:
		s.handleCreateRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetRules returns all rules
func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Convert to response format
	response := RulesConfigResponse{
		Rules: make([]RuleResponse, 0, len(config.Rules)),
	}

	for _, rule := range config.Rules {
		// Ensure MITRE and Tags are never nil (use empty slice if nil)
		mitre := rule.MITRE
		if mitre == nil {
			mitre = []string{}
		}
		tags := rule.Tags
		if tags == nil {
			tags = []string{}
		}

		response.Rules = append(response.Rules, RuleResponse{
			ID:                rule.Name, // Using name as ID for simplicity
			Name:              rule.Name,
			Description:       rule.Description,
			Type:              rule.Type,
			Expression:        rule.Expression,
			Severity:          rule.Severity,
			MITRE:             mitre,
			Tags:              tags,
			Enabled:           rule.Enabled,
			Threshold:         rule.Threshold,
			ThresholdWindow:   rule.ThresholdWindow,
			DistinctField:     rule.DistinctField,
			DistinctThreshold: rule.DistinctThreshold,
			Sequence:          rule.Sequence,
			Actions:           convertActionsToAPI(rule.Actions),
		})
	}

	RespondJSON(w, http.StatusOK, response)
}

// handleCreateRule creates a new rule
func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid request body",
		})
		return
	}

	// Validate required fields
	if req.Name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule name is required",
		})
		return
	}

	if req.Type == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule type is required",
		})
		return
	}

	if req.Expression == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule expression is required",
		})
		return
	}

	if req.Severity == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule severity is required",
		})
		return
	}

	// Validate severity
	if !rules.ValidateSeverity(req.Severity) {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid severity. Must be one of: low, medium, high, critical",
		})
		return
	}

	// Load existing config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Check if rule with same name already exists
	for _, rule := range config.Rules {
		if rule.Name == req.Name {
			RespondJSON(w, http.StatusConflict, map[string]any{
				"error": "A rule with this name already exists",
			})
			return
		}
	}

	// Create new rule
	newRule := &rules.Rule{
		Name:              req.Name,
		Description:       req.Description,
		Type:              req.Type,
		Expression:        req.Expression,
		Severity:          req.Severity,
		MITRE:             req.MITRE,
		Tags:              req.Tags,
		Enabled:           req.Enabled,
		Threshold:         req.Threshold,
		ThresholdWindow:   req.ThresholdWindow,
		DistinctField:     req.DistinctField,
		DistinctThreshold: req.DistinctThreshold,
		Actions:           convertActionsFromAPI(req.Actions),
	}

	// Add to config
	config.Rules = append(config.Rules, newRule)

	// Save config
	if err := s.saveRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to save rules: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Created new rule: %s", req.Name)

	RespondJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"message": "Rule created successfully",
		"rule": RuleResponse{
			ID:                newRule.Name,
			Name:              newRule.Name,
			Description:       newRule.Description,
			Type:              newRule.Type,
			Expression:        newRule.Expression,
			Severity:          newRule.Severity,
			MITRE:             newRule.MITRE,
			Tags:              newRule.Tags,
			Enabled:           newRule.Enabled,
			Threshold:         newRule.Threshold,
			ThresholdWindow:   newRule.ThresholdWindow,
			DistinctField:     newRule.DistinctField,
			DistinctThreshold: newRule.DistinctThreshold,
			Sequence:          newRule.Sequence,
			Actions:           convertActionsToAPI(newRule.Actions),
		},
	})
}

// handleRule handles GET (get specific rule), PUT (update rule), and DELETE (delete rule) requests
func (s *Server) handleRule(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from URL path: /api/rules/{id}
	encodedRuleID := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if encodedRuleID == "" || encodedRuleID == "/api/rules" {
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
		s.handleGetRule(w, r, ruleID)
	case http.MethodPut:
		s.handleUpdateRule(w, r, ruleID)
	case http.MethodDelete:
		s.handleDeleteRule(w, r, ruleID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetRule returns a specific rule
func (s *Server) handleGetRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Find the rule
	for _, rule := range config.Rules {
		if rule.Name == ruleID {
			// Ensure MITRE and Tags are never nil (use empty slice if nil)
			mitre := rule.MITRE
			if mitre == nil {
				mitre = []string{}
			}
			tags := rule.Tags
			if tags == nil {
				tags = []string{}
			}

			RespondJSON(w, http.StatusOK, RuleResponse{
				ID:                rule.Name,
				Name:              rule.Name,
				Description:       rule.Description,
				Type:              rule.Type,
				Expression:        rule.Expression,
				Severity:          rule.Severity,
				MITRE:             mitre,
				Tags:              tags,
				Enabled:           rule.Enabled,
				Threshold:         rule.Threshold,
				ThresholdWindow:   rule.ThresholdWindow,
				DistinctField:     rule.DistinctField,
				DistinctThreshold: rule.DistinctThreshold,
				Sequence:          rule.Sequence,
				Actions:           convertActionsToAPI(rule.Actions),
			})
			return
		}
	}

	RespondJSON(w, http.StatusNotFound, map[string]any{
		"error": "Rule not found",
	})
}

// handleUpdateRule updates an existing rule
func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid request body",
		})
		return
	}

	// Validate required fields
	if req.Name == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule name is required",
		})
		return
	}

	if req.Type == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule type is required",
		})
		return
	}

	if req.Expression == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule expression is required",
		})
		return
	}

	if req.Severity == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule severity is required",
		})
		return
	}

	// Validate severity
	if !rules.ValidateSeverity(req.Severity) {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid severity. Must be one of: low, medium, high, critical",
		})
		return
	}

	// Load existing config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
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
						RespondJSON(w, http.StatusConflict, map[string]any{
							"error": "A rule with this name already exists",
						})
						return
					}
				}
			}

			config.Rules[i].Name = req.Name
			config.Rules[i].Description = req.Description
			config.Rules[i].Type = req.Type
			config.Rules[i].Expression = req.Expression
			config.Rules[i].Severity = req.Severity
			config.Rules[i].MITRE = req.MITRE
			config.Rules[i].Tags = req.Tags
			config.Rules[i].Enabled = req.Enabled
			config.Rules[i].Threshold = req.Threshold
			config.Rules[i].ThresholdWindow = req.ThresholdWindow
			config.Rules[i].DistinctField = req.DistinctField
			config.Rules[i].DistinctThreshold = req.DistinctThreshold
			config.Rules[i].Actions = convertActionsFromAPI(req.Actions)
			found = true
			break
		}
	}

	if !found {
		RespondJSON(w, http.StatusNotFound, map[string]any{
			"error": "Rule not found",
		})
		return
	}

	// Save config
	if err := s.saveRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to save rules: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Updated rule: %s -> %s", ruleID, req.Name)

	RespondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Rule updated successfully",
	})
}

// handleDeleteRule deletes a rule
func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	// Load existing config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Find and remove the rule
	found := false
	newRules := make([]*rules.Rule, 0, len(config.Rules))
	for _, rule := range config.Rules {
		if rule.Name == ruleID {
			found = true
			continue
		}
		newRules = append(newRules, rule)
	}

	if !found {
		RespondJSON(w, http.StatusNotFound, map[string]any{
			"error": "Rule not found",
		})
		return
	}

	config.Rules = newRules

	// Save config
	if err := s.saveRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to save rules: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Deleted rule: %s", ruleID)

	RespondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Rule deleted successfully",
	})
}

// ExecuteRuleRequest represents a request to execute a rule on demand
type ExecuteRuleRequest struct {
	RuleID string `json:"ruleId"`
}

// ExecuteRuleResponse represents the response from executing a rule
type ExecuteRuleResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	AlertsCount   int    `json:"alertsCount"`
	RecordsRead   int    `json:"recordsRead"`
	ExecutionTime int64  `json:"executionTimeMs"`
}

// handleExecuteRule executes a specific rule on demand against the current capture's audit records
func (s *Server) handleExecuteRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ExecuteRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Invalid request body",
		})
		return
	}

	if req.RuleID == "" {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Rule ID is required",
		})
		return
	}

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Load rules config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Find the specific rule
	var targetRule *rules.Rule
	for _, rule := range config.Rules {
		if rule.Name == req.RuleID {
			targetRule = rule
			break
		}
	}

	if targetRule == nil {
		RespondJSON(w, http.StatusNotFound, map[string]any{
			"error": "Rule not found",
		})
		return
	}

	// Execute the rule
	startTime := time.Now()
	alertsCount, recordsRead, err := s.executeRuleOnCapture(targetRule, outDir)
	executionTime := time.Since(startTime).Milliseconds()

	if err != nil {
		log.Printf("[WebUI] Failed to execute rule: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to execute rule: %v", err),
		})
		return
	}

	log.Printf("[WebUI] Executed rule %s: %d alerts from %d records in %dms",
		req.RuleID, alertsCount, recordsRead, executionTime)

	RespondJSON(w, http.StatusOK, ExecuteRuleResponse{
		Success:       true,
		Message:       fmt.Sprintf("Rule executed successfully: %d alerts generated from %d records", alertsCount, recordsRead),
		AlertsCount:   alertsCount,
		RecordsRead:   recordsRead,
		ExecutionTime: executionTime,
	})
}

// ExecuteAllRulesResponse represents the response from executing all rules
type ExecuteAllRulesResponse struct {
	Success       bool             `json:"success"`
	Message       string           `json:"message"`
	TotalAlerts   int              `json:"totalAlerts"`
	TotalRecords  int              `json:"totalRecords"`
	ExecutionTime int64            `json:"executionTimeMs"`
	RuleResults   []RuleExecResult `json:"ruleResults"`
}

// RuleExecResult represents the result of executing a single rule
type RuleExecResult struct {
	RuleName      string `json:"ruleName"`
	AlertsCount   int    `json:"alertsCount"`
	RecordsRead   int    `json:"recordsRead"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	ExecutionTime int64  `json:"executionTimeMs"`
}

// handleExecuteAllRules executes all enabled rules on demand against the current capture's audit records
func (s *Server) handleExecuteAllRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine the output directory
	outDir, _ := s.resolveOutDirFromRequest(r)

	if outDir == "" {
		RespondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "No output directory selected",
		})
		return
	}

	// Load rules config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]any{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Filter for enabled rules only
	enabledRules := make([]*rules.Rule, 0)
	for _, rule := range config.Rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
		}
	}

	if len(enabledRules) == 0 {
		RespondJSON(w, http.StatusBadRequest, map[string]any{
			"error": "No enabled rules found",
		})
		return
	}

	log.Printf("[WebUI] Executing %d enabled rules", len(enabledRules))

	// Execute all enabled rules
	startTime := time.Now()
	totalAlerts := 0
	totalRecords := 0
	results := make([]RuleExecResult, 0, len(enabledRules))

	for _, rule := range enabledRules {
		ruleStartTime := time.Now()
		alertsCount, recordsRead, err := s.executeRuleOnCapture(rule, outDir)
		ruleExecutionTime := time.Since(ruleStartTime).Milliseconds()

		result := RuleExecResult{
			RuleName:      rule.Name,
			AlertsCount:   alertsCount,
			RecordsRead:   recordsRead,
			Success:       err == nil,
			ExecutionTime: ruleExecutionTime,
		}

		if err != nil {
			result.Error = err.Error()
			log.Printf("[WebUI] Error executing rule %s: %v", rule.Name, err)
		} else {
			totalAlerts += alertsCount
			totalRecords += recordsRead
		}

		results = append(results, result)
	}

	executionTime := time.Since(startTime).Milliseconds()

	log.Printf("[WebUI] Executed all rules: %d total alerts from %d total records in %dms",
		totalAlerts, totalRecords, executionTime)

	RespondJSON(w, http.StatusOK, ExecuteAllRulesResponse{
		Success:       true,
		Message:       fmt.Sprintf("Executed %d rules: %d alerts generated from %d records", len(enabledRules), totalAlerts, totalRecords),
		TotalAlerts:   totalAlerts,
		TotalRecords:  totalRecords,
		ExecutionTime: executionTime,
		RuleResults:   results,
	})
}

// executeRuleOnCapture executes a single rule against all relevant audit records in the output directory
func (s *Server) executeRuleOnCapture(rule *rules.Rule, outDir string) (alertsCount int, recordsRead int, err error) {
	// Create a temporary config with just this rule
	tempConfig := &rules.Config{
		Rules: []*rules.Rule{rule},
	}

	// Compile the rule if not already compiled
	if err := rules.CompileRules(tempConfig); err != nil {
		return 0, 0, fmt.Errorf("failed to compile rule: %w", err)
	}

	// Create alert writer for the output directory
	alertWriter, err := rules.NewFileAlertWriter(outDir)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create alert writer: %w", err)
	}
	defer alertWriter.Close()

	// Create a rules engine with just this rule
	// Note: We can't use NewEngine as it expects a file path, so we create manually
	engine := &rules.Engine{}

	// Ensure the output directory exists
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return 0, 0, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize engine with our config
	engine, err = rules.NewEngineFromConfig(tempConfig, alertWriter)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create rules engine: %w", err)
	}

	// Find the audit record file for the rule's type
	auditFile := filepath.Join(outDir, rule.Type+".ncap.gz")
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		// File doesn't exist, no records to process
		return 0, 0, nil
	}

	// Open and read the audit record file
	reader, err := NewAuditRecordReader(auditFile)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read header: %w", err)
	}

	// Process each record
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading record: %v", err)
			continue
		}

		recordsRead++

		// Type assert to AuditRecord
		auditRecord, ok := record.(types.AuditRecord)
		if !ok {
			log.Printf("[WebUI] Record is not an AuditRecord type")
			continue
		}

		// Evaluate the record against the rule
		alerts, err := engine.Evaluate(auditRecord)
		if err != nil {
			log.Printf("[WebUI] Error evaluating record: %v", err)
			continue
		}

		alertsCount += alerts
	}

	return alertsCount, recordsRead, nil
}
