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

	"gopkg.in/yaml.v2"

	"github.com/dreadl0ck/netcap/rules"
)

// handleRuleSets handles GET request to list all rule sets
func (s *Server) handleRuleSets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rulesFolder := s.getRulesFolderPath()

	// Load the full rules config (includes embedded + file overrides)
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	// Get embedded rule set info (names and descriptions)
	embeddedInfo, err := rules.GetEmbeddedRuleSetInfo()
	if err != nil {
		log.Printf("[WebUI] Warning: failed to get embedded rule set info: %v", err)
		embeddedInfo = make(map[string]rules.EmbeddedRuleSetInfo)
	}
	embeddedSet := make(map[string]bool)
	for name := range embeddedInfo {
		embeddedSet[name] = true
	}

	// Get list of file-based rule sets (for override detection)
	fileBasedSet := make(map[string]bool)
	if entries, err := os.ReadDir(rulesFolder); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yml") {
				name := strings.TrimSuffix(entry.Name(), ".yml")
				fileBasedSet[name] = true
			}
		}
	}

	// Build a map of all unique rule sets from the loaded config
	ruleSetMap := make(map[string]*RuleSetInfo)

	for _, rule := range config.Rules {
		// Find the ruleset tag
		ruleSetName := ""
		isEmbedded := false
		for _, tag := range rule.Tags {
			if strings.HasPrefix(tag, "ruleset:") {
				ruleSetName = strings.TrimPrefix(tag, "ruleset:")
			}
			if tag == "embedded" {
				isEmbedded = true
			}
		}

		if ruleSetName == "" {
			continue // Skip rules without a ruleset tag
		}

		// Get or create rule set info
		info, exists := ruleSetMap[ruleSetName]
		if !exists {
			info = &RuleSetInfo{
				Name:       ruleSetName,
				Filename:   ruleSetName + ".yml",
				IsEmbedded: embeddedSet[ruleSetName],
			}
			ruleSetMap[ruleSetName] = info
		}

		// Count rules and track enabled status
		info.RuleCount++
		if rule.Enabled {
			info.Enabled = true
		}

		// Track if this rule is embedded (any embedded rule means the set is embedded)
		if isEmbedded {
			info.IsEmbedded = true
		}
	}

	// Now set IsOverridden for embedded rule sets that have file overrides
	for name, info := range ruleSetMap {
		if info.IsEmbedded && fileBasedSet[name] {
			info.IsOverridden = true
		}
	}

	// Load descriptions from files or embedded
	for name, info := range ruleSetMap {
		var description string

		// First try to load from file (override takes priority)
		filePath := filepath.Join(rulesFolder, name+".yml")
		if fileData, err := os.ReadFile(filePath); err == nil {
			var fileConfig rules.Config
			if err := yaml.Unmarshal(fileData, &fileConfig); err == nil && fileConfig.Description != "" {
				description = fileConfig.Description
			}
		}

		// If no file description and it's embedded, use embedded description
		if description == "" {
			if embeddedRuleSetInfo, ok := embeddedInfo[name]; ok && embeddedRuleSetInfo.Description != "" {
				description = embeddedRuleSetInfo.Description
			}
		}

		// Fallback: generate from filename
		if description == "" {
			description = strings.ReplaceAll(name, "_", " ")
			description = strings.Title(description)
		}

		info.Description = description
	}

	// Convert map to slice
	ruleSets := make([]RuleSetInfo, 0, len(ruleSetMap))
	for _, info := range ruleSetMap {
		ruleSets = append(ruleSets, *info)
	}

	RespondJSON(w, http.StatusOK, RuleSetsResponse{
		RuleSets: ruleSets,
	})
}

// handleRuleSet handles PUT request to enable/disable a rule set
func (s *Server) handleRuleSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract rule set name from URL path: /api/rule-sets/{name}
	encodedRuleSetName := strings.TrimPrefix(r.URL.Path, "/api/rule-sets/")
	if encodedRuleSetName == "" || encodedRuleSetName == "/api/rule-sets" {
		http.Error(w, "Rule set name required", http.StatusBadRequest)
		return
	}

	// URL-decode the rule set name
	ruleSetName, err := url.PathUnescape(encodedRuleSetName)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid rule set name encoding",
		})
		return
	}

	var req UpdateRuleSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid request body",
		})
		return
	}

	// Load existing config
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	ruleSetTag := "ruleset:" + ruleSetName
	updatedCount := 0
	var updatedRules []*rules.Rule

	// Update all rules in this rule set
	for i, rule := range config.Rules {
		// Check if this rule belongs to this rule set
		hasRuleSetTag := false
		for _, tag := range rule.Tags {
			if tag == ruleSetTag {
				hasRuleSetTag = true
				break
			}
		}

		if hasRuleSetTag {
			log.Printf("[WebUI] Updating rule %s: enabled=%v -> %v", rule.Name, rule.Enabled, req.Enabled)
			config.Rules[i].Enabled = req.Enabled
			updatedRules = append(updatedRules, config.Rules[i])
			updatedCount++
		}
	}

	if updatedCount == 0 {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Rule set not found",
		})
		return
	}

	// Save the rule set as a file override (this applies to both embedded and file-based rules)
	if err := s.saveRuleSetOverride(ruleSetName, updatedRules); err != nil {
		log.Printf("[WebUI] Failed to save rule set override: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to save rules: %v", err),
		})
		return
	}

	// Invalidate cache to reload with new settings
	s.invalidateRulesCache()

	// Reload the rules engine in the collector if available
	s.mu.RLock()
	collector := s.collector
	s.mu.RUnlock()

	if collector != nil {
		if err := collector.ReloadRulesEngine(); err != nil {
			log.Printf("[WebUI] Warning: failed to reload rules engine: %v", err)
			// Don't fail the request, just log the warning
		} else {
			log.Printf("[WebUI] Rules engine reloaded successfully")
		}
	}

	status := "enabled"
	if !req.Enabled {
		status = "disabled"
	}

	log.Printf("[WebUI] Rule set %s %s (%d rules affected)", ruleSetName, status, updatedCount)

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success":       true,
		"message":       fmt.Sprintf("Rule set %s %s (%d rules affected)", ruleSetName, status, updatedCount),
		"rulesAffected": updatedCount,
	})
}

// saveRuleSetOverride saves a rule set to disk, creating an override file for embedded rules
func (s *Server) saveRuleSetOverride(ruleSetName string, rulesToSave []*rules.Rule) error {
	rulesFolder := s.getRulesFolderPath()

	// Create rules folder if it doesn't exist
	if err := os.MkdirAll(rulesFolder, 0755); err != nil {
		return fmt.Errorf("failed to create rules folder: %w", err)
	}

	// Prepare rules for saving (remove internal tags)
	rulesForSave := make([]*rules.Rule, len(rulesToSave))
	for i, rule := range rulesToSave {
		// Create a copy of the rule
		ruleCopy := rules.Rule{
			Name:            rule.Name,
			Description:     rule.Description,
			Type:            rule.Type,
			Expression:      rule.Expression,
			Severity:        rule.Severity,
			MITRE:           rule.MITRE,
			Enabled:         rule.Enabled,
			Threshold:       rule.Threshold,
			ThresholdWindow: rule.ThresholdWindow,
			Actions:         rule.Actions,
		}
		// Filter out internal tags (ruleset: and embedded)
		newTags := make([]string, 0, len(rule.Tags))
		for _, tag := range rule.Tags {
			if !strings.HasPrefix(tag, "ruleset:") && tag != "embedded" {
				newTags = append(newTags, tag)
			}
		}
		ruleCopy.Tags = newTags
		rulesForSave[i] = &ruleCopy
	}

	// Try to preserve description from existing file or embedded
	var description string
	filePath := filepath.Join(rulesFolder, ruleSetName+".yml")
	if existingData, err := os.ReadFile(filePath); err == nil {
		var existingConfig rules.Config
		if err := yaml.Unmarshal(existingData, &existingConfig); err == nil {
			description = existingConfig.Description
		}
	}

	// If no existing description, generate a friendly one
	if description == "" {
		description = strings.ReplaceAll(ruleSetName, "_", " ")
		description = strings.Title(description)
	}

	ruleSetConfig := &rules.Config{
		Description: description,
		Rules:       rulesForSave,
	}

	data, err := yaml.Marshal(ruleSetConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal rule set: %w", err)
	}

	log.Printf("[WebUI] Writing %d rules to override file %s", len(rulesForSave), filePath)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule set file: %w", err)
	}

	return nil
}

