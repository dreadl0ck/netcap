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
	
	// Read all .yml files from the rules folder
	entries, err := os.ReadDir(rulesFolder)
	if err != nil {
		log.Printf("[WebUI] Failed to read rules folder: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to read rules folder: %v", err),
		})
		return
	}

	// Load the full rules config to check enabled status
	config, err := s.loadRulesConfig()
	if err != nil {
		log.Printf("[WebUI] Failed to load rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	ruleSets := make([]RuleSetInfo, 0)
	
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		filename := entry.Name()
		ruleSetName := strings.TrimSuffix(filename, ".yml")
		ruleSetTag := "ruleset:" + ruleSetName

		// Load the YAML file to get the description from the config
		filePath := filepath.Join(rulesFolder, filename)
		fileData, err := os.ReadFile(filePath)
		var description string
		if err == nil {
			var fileConfig rules.Config
			if err := yaml.Unmarshal(fileData, &fileConfig); err == nil {
				description = fileConfig.Description
			}
		}

		// Count rules in this set and check if any are enabled
		ruleCount := 0
		hasEnabledRule := false
		
		for _, rule := range config.Rules {
			// Check if this rule belongs to this rule set
			hasRuleSetTag := false
			for _, tag := range rule.Tags {
				if tag == ruleSetTag {
					hasRuleSetTag = true
					break
				}
			}
			
			if hasRuleSetTag {
				ruleCount++
				if rule.Enabled {
					hasEnabledRule = true
				}
			}
		}

		// If no description from config file, use a friendly name from filename
		if description == "" {
			// Convert filename to a more readable format
			description = strings.ReplaceAll(ruleSetName, "_", " ")
			description = strings.Title(description)
		}

		// A rule set is considered enabled if at least one rule is enabled
		isEnabled := ruleCount > 0 && hasEnabledRule

		ruleSets = append(ruleSets, RuleSetInfo{
			Name:        ruleSetName,
			Filename:    filename,
			RuleCount:   ruleCount,
			Enabled:     isEnabled,
			Description: description,
		})
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
			updatedCount++
		}
	}

	if updatedCount == 0 {
		RespondJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "Rule set not found",
		})
		return
	}

	log.Printf("[WebUI] Attempting to save rules config with %d total rules", len(config.Rules))

	// Save the updated config
	if err := s.saveRulesConfig(config); err != nil {
		log.Printf("[WebUI] Failed to save rules config: %v", err)
		RespondJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("Failed to save rules: %v", err),
		})
		return
	}

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
		"success": true,
		"message": fmt.Sprintf("Rule set %s %s (%d rules affected)", ruleSetName, status, updatedCount),
		"rulesAffected": updatedCount,
	})
}

