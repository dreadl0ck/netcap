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

package injection

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/filter"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// Engine is the core injection engine that evaluates rules and executes actions.
type Engine struct {
	config  *Config
	eConfig *EngineConfig

	// Mutex for thread-safe access
	mu sync.RWMutex

	// Statistics
	stats *EngineStats

	// Action log file
	logFile *os.File

	// Shutdown channel
	shutdown chan struct{}
}

// EngineStats tracks injection engine statistics using atomic operations for counters.
type EngineStats struct {
	// Mutex only for map operations (RuleMatches and ActionCounts)
	mu sync.Mutex

	// Atomic counters for high-performance updates
	PacketsProcessed atomic.Uint64
	PacketsMatched   atomic.Uint64
	ActionsExecuted  atomic.Uint64
	PacketsDropped   atomic.Uint64
	PacketsModified  atomic.Uint64
	PacketsInjected  atomic.Uint64
	Errors           atomic.Uint64

	// Per-rule match counts (requires mutex)
	RuleMatches map[string]uint64

	// Per-action counts (requires mutex)
	ActionCounts map[Action]uint64

	// Start time
	StartTime time.Time
}

// NewEngineStats creates new statistics tracker.
func NewEngineStats() *EngineStats {
	return &EngineStats{
		RuleMatches:  make(map[string]uint64),
		ActionCounts: make(map[Action]uint64),
		StartTime:    time.Now(),
	}
}

// NewEngine creates a new injection engine with the given configuration.
func NewEngine(rulesPath string, eConfig *EngineConfig) (*Engine, error) {
	if eConfig == nil {
		cfg := DefaultEngineConfig
		eConfig = &cfg
	}

	if rulesPath == "" && eConfig.RulesPath != "" {
		rulesPath = eConfig.RulesPath
	}

	// Load rules
	config, err := LoadRules(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	// Compile rules
	if err := CompileRules(config); err != nil {
		return nil, fmt.Errorf("failed to compile rules: %w", err)
	}

	// Sort rules by priority (higher first)
	sort.Slice(config.Rules, func(i, j int) bool {
		return config.Rules[i].Priority > config.Rules[j].Priority
	})

	engine := &Engine{
		config:   config,
		eConfig:  eConfig,
		stats:    NewEngineStats(),
		shutdown: make(chan struct{}),
	}

	// Open action log file if configured
	if eConfig.LogActions && eConfig.LogFile != "" {
		logFile, err := os.OpenFile(eConfig.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		engine.logFile = logFile
	}

	return engine, nil
}

// ProcessPacket evaluates all rules against a packet and returns actions to perform.
func (e *Engine) ProcessPacket(pkt gopacket.Packet, iface string) ([]*ActionResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Update stats (atomic - no lock needed)
	e.stats.PacketsProcessed.Add(1)

	// Create injection context
	ctx := NewInjectionContext(pkt, iface)

	var results []*ActionResult

	// Evaluate each rule
	for _, rule := range e.config.Rules {
		if !rule.Enabled || !rule.IsCompiled() {
			continue
		}

		// Determine record type for this rule
		recordType, err := parseRecordType(rule.Type)
		if err != nil {
			continue // Skip rules with invalid types
		}

		// Create audit record for expression evaluation
		record := e.createAuditRecord(ctx, recordType)
		if record == nil {
			continue
		}

		// Evaluate expression
		match, err := filter.EvaluateExpression(rule.GetCompiled(), record)
		if err != nil {
			e.stats.Errors.Add(1)
			continue
		}

		if !match {
			continue
		}

		// Rule matched (atomic for counter, mutex for map)
		e.stats.PacketsMatched.Add(1)
		e.stats.mu.Lock()
		e.stats.RuleMatches[rule.Name]++
		e.stats.mu.Unlock()

		ctx.MatchedRules = append(ctx.MatchedRules, rule.Name)

		// Execute action
		result, err := e.executeAction(ctx, rule)
		if err != nil {
			e.stats.Errors.Add(1)

			if e.eConfig.Verbose {
				fmt.Printf("Error executing action for rule %s: %v\n", rule.Name, err)
			}
			continue
		}

		if result != nil {
			result.RuleName = rule.Name
			results = append(results, result)

			// Log action
			if e.eConfig.LogActions {
				e.logAction(result)
			}
		}

		// Stop evaluation if configured
		if rule.StopOnMatch {
			break
		}
	}

	// If no rules matched and default action is drop, add drop result
	if len(results) == 0 && e.eConfig.DefaultAction == ActionDrop {
		results = append(results, &ActionResult{
			Action:    ActionDrop,
			Success:   true,
			Drop:      true,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

// executeAction executes the action specified by a rule.
func (e *Engine) executeAction(ctx *InjectionContext, rule *Rule) (*ActionResult, error) {
	// Update action stats (atomic for counter, mutex for map)
	e.stats.ActionsExecuted.Add(1)
	e.stats.mu.Lock()
	e.stats.ActionCounts[rule.Action]++
	e.stats.mu.Unlock()

	// Handle simple verdict actions
	switch rule.Action {
	case ActionAccept:
		return &ActionResult{
			Action:    ActionAccept,
			Success:   true,
			Timestamp: time.Now(),
		}, nil

	case ActionDrop:
		e.stats.PacketsDropped.Add(1)

		return &ActionResult{
			Action:    ActionDrop,
			Success:   true,
			Drop:      true,
			Timestamp: time.Now(),
		}, nil
	}

	// Get action handler for complex actions
	handler, err := GetActionHandler(rule.Action)
	if err != nil {
		return nil, err
	}

	if handler == nil {
		return nil, fmt.Errorf("no handler for action: %s", rule.Action)
	}

	// Execute the action
	result, err := handler.Execute(ctx, rule.ActionConfig)
	if err != nil {
		return nil, err
	}

	// Update statistics based on result (all atomic)
	if result != nil {
		if result.Drop {
			e.stats.PacketsDropped.Add(1)
		}
		if result.ModifiedPacket != nil {
			e.stats.PacketsModified.Add(1)
		}
		if len(result.InjectPackets) > 0 {
			e.stats.PacketsInjected.Add(uint64(len(result.InjectPackets)))
		}
	}

	return result, nil
}

// createAuditRecord creates an audit record from the injection context for rule evaluation.
func (e *Engine) createAuditRecord(ctx *InjectionContext, recordType types.Type) types.AuditRecord {
	// Use the audit record if already set
	if ctx.AuditRecord != nil {
		return ctx.AuditRecord
	}

	// Initialize a new record of the appropriate type
	record := netio.InitRecord(recordType)
	if record == nil {
		return nil
	}

	auditRecord, ok := record.(types.AuditRecord)
	if !ok {
		return nil
	}

	// Populate common fields based on context
	e.populateRecordFromContext(auditRecord, ctx)

	return auditRecord
}

// populateRecordFromContext fills in audit record fields from the injection context.
func (e *Engine) populateRecordFromContext(record types.AuditRecord, ctx *InjectionContext) {
	// This is a simplified population - in practice, you'd use reflection or
	// type switches to set specific fields based on the record type
	timestamp := ctx.Timestamp.UnixNano()

	switch r := record.(type) {
	case *types.TCP:
		r.Timestamp = timestamp
		r.SrcIP = ctx.SrcIP()
		r.DstIP = ctx.DstIP()
		if ctx.TCP != nil {
			r.SrcPort = int32(ctx.TCP.SrcPort)
			r.DstPort = int32(ctx.TCP.DstPort)
			r.SeqNum = ctx.TCP.Seq
			r.AckNum = ctx.TCP.Ack
			r.SYN = ctx.TCP.SYN
			r.ACK = ctx.TCP.ACK
			r.FIN = ctx.TCP.FIN
			r.RST = ctx.TCP.RST
			r.PSH = ctx.TCP.PSH
			r.URG = ctx.TCP.URG
		}
		if len(ctx.Payload) > 0 {
			r.PayloadSize = int32(len(ctx.Payload))
		}

	case *types.UDP:
		r.Timestamp = timestamp
		r.SrcIP = ctx.SrcIP()
		r.DstIP = ctx.DstIP()
		if ctx.UDP != nil {
			r.SrcPort = int32(ctx.UDP.SrcPort)
			r.DstPort = int32(ctx.UDP.DstPort)
			r.Length = int32(ctx.UDP.Length)
		}
		if len(ctx.Payload) > 0 {
			r.PayloadSize = int32(len(ctx.Payload))
		}

	case *types.DNS:
		r.Timestamp = timestamp
		if ctx.DNS != nil {
			r.ID = int32(ctx.DNS.ID)
			r.QR = ctx.DNS.QR
			r.OpCode = int32(ctx.DNS.OpCode)
			r.AA = ctx.DNS.AA
			r.TC = ctx.DNS.TC
			r.RD = ctx.DNS.RD
			r.RA = ctx.DNS.RA
			r.ResponseCode = int32(ctx.DNS.ResponseCode)
			r.QDCount = int32(ctx.DNS.QDCount)
			r.ANCount = int32(ctx.DNS.ANCount)
		}

	case *types.ARP:
		r.Timestamp = timestamp
		if ctx.ARP != nil {
			r.AddrType = int32(ctx.ARP.AddrType)
			r.Protocol = int32(ctx.ARP.Protocol)
			r.Operation = int32(ctx.ARP.Operation)
			r.SrcHwAddress = net.HardwareAddr(ctx.ARP.SourceHwAddress).String()
			r.SrcProtocolAddress = net.IP(ctx.ARP.SourceProtAddress).String()
			r.DstHwAddress = net.HardwareAddr(ctx.ARP.DstHwAddress).String()
			r.DstProtocolAddress = net.IP(ctx.ARP.DstProtAddress).String()
		}

	case *types.IPv4:
		r.Timestamp = timestamp
		if ctx.IPv4 != nil {
			r.Version = int32(ctx.IPv4.Version)
			r.IHL = int32(ctx.IPv4.IHL)
			r.TOS = int32(ctx.IPv4.TOS)
			r.Length = int32(ctx.IPv4.Length)
			r.Id = int32(ctx.IPv4.Id)
			r.TTL = int32(ctx.IPv4.TTL)
			r.Protocol = int32(ctx.IPv4.Protocol)
			r.SrcIP = ctx.IPv4.SrcIP.String()
			r.DstIP = ctx.IPv4.DstIP.String()
		}

	case *types.IPv6:
		r.Timestamp = timestamp
		if ctx.IPv6 != nil {
			r.Version = int32(ctx.IPv6.Version)
			r.TrafficClass = int32(ctx.IPv6.TrafficClass)
			r.FlowLabel = ctx.IPv6.FlowLabel
			r.Length = int32(ctx.IPv6.Length)
			r.NextHeader = int32(ctx.IPv6.NextHeader)
			r.HopLimit = int32(ctx.IPv6.HopLimit)
			r.SrcIP = ctx.IPv6.SrcIP.String()
			r.DstIP = ctx.IPv6.DstIP.String()
		}

	case *types.Ethernet:
		r.Timestamp = timestamp
		if ctx.Ethernet != nil {
			r.SrcMAC = ctx.Ethernet.SrcMAC.String()
			r.DstMAC = ctx.Ethernet.DstMAC.String()
			r.EthernetType = int32(ctx.Ethernet.EthernetType)
		}

		// Add more type cases as needed
	}
}

// logAction writes an action to the log file.
func (e *Engine) logAction(result *ActionResult) {
	if e.logFile == nil {
		return
	}

	entry := map[string]interface{}{
		"timestamp": result.Timestamp.Format(time.RFC3339Nano),
		"rule":      result.RuleName,
		"action":    result.Action,
		"success":   result.Success,
		"details":   result.Details,
	}

	if result.Error != nil {
		entry["error"] = result.Error.Error()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		if e.eConfig.Verbose {
			fmt.Printf("Failed to marshal log entry: %v\n", err)
		}
		return
	}

	if _, err := e.logFile.Write(data); err != nil {
		if e.eConfig.Verbose {
			fmt.Printf("Failed to write log entry: %v\n", err)
		}
		return
	}
	if _, err := e.logFile.WriteString("\n"); err != nil {
		if e.eConfig.Verbose {
			fmt.Printf("Failed to write log newline: %v\n", err)
		}
	}
}

// EngineStatsSnapshot is a snapshot of engine statistics for reporting.
type EngineStatsSnapshot struct {
	PacketsProcessed uint64
	PacketsMatched   uint64
	ActionsExecuted  uint64
	PacketsDropped   uint64
	PacketsModified  uint64
	PacketsInjected  uint64
	Errors           uint64
	RuleMatches      map[string]uint64
	ActionCounts     map[Action]uint64
	StartTime        time.Time
}

// GetStats returns a snapshot of the current statistics.
func (e *Engine) GetStats() EngineStatsSnapshot {
	// Read atomic values (no lock needed)
	stats := EngineStatsSnapshot{
		PacketsProcessed: e.stats.PacketsProcessed.Load(),
		PacketsMatched:   e.stats.PacketsMatched.Load(),
		ActionsExecuted:  e.stats.ActionsExecuted.Load(),
		PacketsDropped:   e.stats.PacketsDropped.Load(),
		PacketsModified:  e.stats.PacketsModified.Load(),
		PacketsInjected:  e.stats.PacketsInjected.Load(),
		Errors:           e.stats.Errors.Load(),
		RuleMatches:      make(map[string]uint64),
		ActionCounts:     make(map[Action]uint64),
		StartTime:        e.stats.StartTime,
	}

	// Lock only for map copies
	e.stats.mu.Lock()
	for k, v := range e.stats.RuleMatches {
		stats.RuleMatches[k] = v
	}
	for k, v := range e.stats.ActionCounts {
		stats.ActionCounts[k] = v
	}
	e.stats.mu.Unlock()

	return stats
}

// GetRules returns the loaded rules.
func (e *Engine) GetRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.config.Rules
}

// GetEnabledRulesCount returns the number of enabled rules.
func (e *Engine) GetEnabledRulesCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	count := 0
	for _, rule := range e.config.Rules {
		if rule.Enabled {
			count++
		}
	}

	return count
}

// Close shuts down the engine and releases resources.
func (e *Engine) Close() error {
	close(e.shutdown)

	if e.logFile != nil {
		return e.logFile.Close()
	}

	return nil
}

// PrintBanner prints the warning banner for the injection engine.
func PrintBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    NETCAP INJECTION ENGINE - WARNING                         ║
║                                                                              ║
║  This tool is designed for authorized security testing and research only.   ║
║  Unauthorized interception or modification of network traffic may violate   ║
║  local, state, and federal laws.                                             ║
║                                                                              ║
║  By using this tool, you acknowledge that:                                   ║
║  - You have proper authorization to test the target network                  ║
║  - You understand the legal implications of packet manipulation              ║
║  - You accept full responsibility for your actions                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
