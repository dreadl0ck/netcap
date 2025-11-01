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

	"github.com/dreadl0ck/netcap/cmd/capture/service"
)

// runServiceMode starts the service mode server for multi-file upload and analysis
func runServiceMode() {
	fmt.Println("Starting Netcap in service mode...")
	fmt.Printf("HTTP server will listen on: http://%s\n", *flagHTTP)

	// Create service configuration
	config := &service.Config{
		MaxFileSize:     *flagServiceMaxFileSize,
		MaxAnalysisHour: *flagServiceMaxPerHour,
		SessionExpiry:   *flagServiceExpiry,
		CleanupInterval: *flagServiceCleanup,
		MaxStorageBytes: *flagServiceMaxStorage,
	}

	// Set data directory from flag or use default
	if *flagServiceDataDir != "" {
		config.DataDir = *flagServiceDataDir
	} else {
		config.DataDir = service.DefaultConfig().DataDir
	}

	fmt.Printf("Data directory: %s\n", config.DataDir)
	fmt.Printf("Max file size: %d bytes\n", config.MaxFileSize)
	fmt.Printf("Max analyses per hour per IP: %d\n", config.MaxAnalysisHour)
	fmt.Printf("Session expiry: %d minutes\n", config.SessionExpiry)

	// Create and start server
	server, err := service.NewServer(*flagHTTP, config, *flagDPI)
	if err != nil {
		log.Fatalf("Failed to create service server: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			serverErrChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case err := <-serverErrChan:
		log.Fatalf("Service server error: %v", err)
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal %v, shutting down gracefully...\n", sig)

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Stop(ctx); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}

		fmt.Println("Service mode stopped")
	}
}
