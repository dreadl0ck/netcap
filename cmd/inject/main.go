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

// Package inject provides the inject subcommand for inline packet manipulation.
package inject

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/injection"
	"github.com/dreadl0ck/netcap/io"
)

// RunWithContext executes the inject subcommand.
func RunWithContext(ctx context.Context, cmd *cli.Command) error {
	// Print banner unless suppressed
	if !flagNoWarning {
		injection.PrintBanner()
	}

	// Check if nfqueue is supported on this platform
	if !injection.IsNFQueueSupported() {
		return fmt.Errorf("the inject command requires Linux with nfqueue support")
	}

	// Validate required flags
	if flagRules == "" {
		return fmt.Errorf("rules path is required (-rules)")
	}

	// Create engine configuration
	engineConfig := &injection.EngineConfig{
		RulesPath:      flagRules,
		QueueNum:       uint16(flagQueue),
		Interface:      flagInterface,
		AutoIPTables:   flagAutoIPTables,
		IPTablesTarget: flagIPTablesTarget,
		Verbose:        flagVerbose,
		DryRun:         flagDryRun,
		LogActions:     flagLogActions,
		LogFile:        flagLogFile,
		MaxQueueLen:    uint32(flagMaxQueueLen),
		DefaultAction:  injection.ActionAccept,
	}

	// Create injection engine
	engine, err := injection.NewEngine(flagRules, engineConfig)
	if err != nil {
		return fmt.Errorf("failed to create injection engine: %w", err)
	}
	defer engine.Close()

	// Handle validation mode
	if flagValidate {
		return validateRules(engine)
	}

	// Handle list rules mode
	if flagListRules {
		return listRules(engine)
	}

	// Print startup information
	printStartupInfo(engine, engineConfig)

	// Create nfqueue handler
	handler, err := injection.NewNFQueueHandler(engine, engineConfig)
	if err != nil {
		return fmt.Errorf("failed to create nfqueue handler: %w", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start processing
	if err := handler.Start(); err != nil {
		return fmt.Errorf("failed to start nfqueue handler: %w", err)
	}

	fmt.Println("\nInjection engine running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		fmt.Println("\nContext cancelled, shutting down...")
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
	}

	// Stop handler
	if err := handler.Stop(); err != nil {
		fmt.Printf("Warning: error stopping handler: %v\n", err)
	}

	// Print statistics
	printStats(engine, handler)

	return nil
}

// validateRules validates the loaded rules and reports any issues.
func validateRules(engine *injection.Engine) error {
	rules := engine.GetRules()
	errors := 0

	fmt.Println("Validating rules...")
	fmt.Println()

	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			fmt.Printf("  [ERROR] %s: %v\n", rule.Name, err)
			errors++
		} else if rule.Enabled && !rule.IsCompiled() {
			fmt.Printf("  [ERROR] %s: failed to compile expression\n", rule.Name)
			errors++
		} else if rule.Enabled {
			fmt.Printf("  [OK] %s\n", rule.Name)
		} else {
			fmt.Printf("  [DISABLED] %s\n", rule.Name)
		}
	}

	fmt.Println()
	if errors > 0 {
		return fmt.Errorf("validation failed with %d error(s)", errors)
	}

	fmt.Printf("All %d rules validated successfully.\n", len(rules))
	return nil
}

// listRules prints the loaded rules in a formatted table.
func listRules(engine *injection.Engine) error {
	rules := engine.GetRules()

	if len(rules) == 0 {
		fmt.Println("No rules loaded.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "NAME\tTYPE\tACTION\tENABLED\tPRIORITY\tDESCRIPTION")
	fmt.Fprintln(w, "----\t----\t------\t-------\t--------\t-----------")

	for _, rule := range rules {
		enabled := "no"
		if rule.Enabled {
			enabled = "yes"
		}

		// Truncate description if too long
		desc := rule.Description
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			rule.Name,
			rule.Type,
			rule.Action,
			enabled,
			rule.Priority,
			desc,
		)
	}

	w.Flush()

	fmt.Printf("\nTotal: %d rules (%d enabled)\n", len(rules), engine.GetEnabledRulesCount())

	return nil
}

// printStartupInfo prints information about the injection engine configuration.
func printStartupInfo(engine *injection.Engine, config *injection.EngineConfig) {
	io.PrintLogo()

	fmt.Println("Injection Engine Configuration:")
	fmt.Println("================================")
	fmt.Printf("  Rules Path:      %s\n", config.RulesPath)
	fmt.Printf("  Queue Number:    %d\n", config.QueueNum)
	fmt.Printf("  Interface:       %s\n", nvl(config.Interface, "(not specified)"))
	fmt.Printf("  Auto iptables:   %v\n", config.AutoIPTables)
	if config.IPTablesTarget != "" {
		fmt.Printf("  iptables Target: %s\n", config.IPTablesTarget)
	}
	fmt.Printf("  Verbose:         %v\n", config.Verbose)
	fmt.Printf("  Dry Run:         %v\n", config.DryRun)
	fmt.Printf("  Log Actions:     %v\n", config.LogActions)
	if config.LogActions {
		fmt.Printf("  Log File:        %s\n", config.LogFile)
	}
	fmt.Printf("  Max Queue Len:   %d\n", config.MaxQueueLen)
	fmt.Printf("  Default Action:  %s\n", config.DefaultAction)
	fmt.Println()
	fmt.Printf("Loaded Rules: %d (%d enabled)\n", len(engine.GetRules()), engine.GetEnabledRulesCount())
	fmt.Println()
}

// printStats prints statistics after shutdown.
func printStats(engine *injection.Engine, handler *injection.NFQueueHandler) {
	fmt.Println()
	fmt.Println("Statistics:")
	fmt.Println("===========")

	// Engine stats
	stats := engine.GetStats()
	fmt.Printf("  Runtime:           %s\n", time.Since(stats.StartTime).Round(time.Second))
	fmt.Printf("  Packets Processed: %d\n", stats.PacketsProcessed)
	fmt.Printf("  Packets Matched:   %d\n", stats.PacketsMatched)
	fmt.Printf("  Actions Executed:  %d\n", stats.ActionsExecuted)
	fmt.Printf("  Packets Dropped:   %d\n", stats.PacketsDropped)
	fmt.Printf("  Packets Modified:  %d\n", stats.PacketsModified)
	fmt.Printf("  Packets Injected:  %d\n", stats.PacketsInjected)
	fmt.Printf("  Errors:            %d\n", stats.Errors)

	// Handler stats
	received, accepted, dropped, modified := handler.GetStats()
	fmt.Println()
	fmt.Println("NFQueue Handler Stats:")
	fmt.Printf("  Received:          %d\n", received)
	fmt.Printf("  Accepted:          %d\n", accepted)
	fmt.Printf("  Dropped:           %d\n", dropped)
	fmt.Printf("  Modified:          %d\n", modified)

	// Per-rule matches
	if len(stats.RuleMatches) > 0 {
		fmt.Println()
		fmt.Println("Rule Matches:")
		for rule, count := range stats.RuleMatches {
			fmt.Printf("  %s: %d\n", rule, count)
		}
	}

	// Per-action counts
	if len(stats.ActionCounts) > 0 {
		fmt.Println()
		fmt.Println("Action Counts:")
		for action, count := range stats.ActionCounts {
			fmt.Printf("  %s: %d\n", action, count)
		}
	}
}

// nvl returns the value if not empty, otherwise returns the default.
func nvl(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

