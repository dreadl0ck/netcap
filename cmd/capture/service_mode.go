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

package capture

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
)

// runServiceMode starts the service mode server for multi-file upload and analysis
func runServiceMode() {
	fmt.Println("Starting Netcap in service mode...")
	fmt.Printf("HTTP server will listen on: http://%s\n", *flagHTTP)

	// Create service configuration
	serviceConfig := &webui.ServiceConfig{
		MaxFileSize:     *flagServiceMaxFileSize,
		MaxAnalysisHour: *flagServiceMaxPerHour,
		SessionExpiry:   *flagServiceExpiry,
		CleanupInterval: *flagServiceCleanup,
		MaxStorageBytes: *flagServiceMaxStorage,
	}

	// Set data directory from flag or use default
	if *flagServiceDataDir != "" {
		serviceConfig.DataDir = *flagServiceDataDir
	} else {
		serviceConfig.DataDir = webui.DefaultServiceConfig().DataDir
	}

	fmt.Printf("Data directory: %s\n", serviceConfig.DataDir)
	fmt.Printf("Max file size: %d bytes\n", serviceConfig.MaxFileSize)
	fmt.Printf("Max analyses per hour per IP: %d\n", serviceConfig.MaxAnalysisHour)
	fmt.Printf("Session expiry: %d minutes\n", serviceConfig.SessionExpiry)

	// Create unified server in service mode
	server := webui.NewServer(
		*flagHTTP,
		serviceConfig.DataDir,
		nil,         // no input files in service mode
		"",          // no custom assets path
		false,       // debug logging
		*flagDPI,    // DPI configuration
		true,        // isServiceMode = true
		serviceConfig, // service configuration
	)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	
	fmt.Printf("\n%sWeb UI available at: http://%s%s\n\n", "\033[32m", *flagHTTP, "\033[0m")

	// Wait for shutdown signal
	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down gracefully...\n", sig)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	fmt.Println("Service mode stopped")
}
