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

package try

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dreadl0ck/netcap/io"
)

// Run starts the try service with file upload and analysis capabilities
func Run() {
	// Parse commandline flags
	fs.Usage = printUsage
	err := fs.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	if *flagGenerateConfig {
		io.GenerateConfig(fs, "try")
		return
	}

	if *flagHTTP == "" {
		log.Fatal("error: -http flag is required to start the try service (e.g., -http :7070)")
	}

	printHeader()

	// Create server with configuration
	server, err := NewServer(*flagHTTP, *flagDataDir, *flagDPI)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("\nNetcap Try Service running on http://%s\n", *flagHTTP)
	fmt.Printf("Data directory: %s\n", *flagDataDir)
	fmt.Printf("DPI enabled: %v\n", *flagDPI)
	fmt.Println("Upload PCAP files for analysis via the web interface")
	fmt.Println("Press Ctrl+C to stop the server")

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutdown signal received, stopping server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	fmt.Println("Server stopped successfully")
}

func printHeader() {
	io.PrintLogo()
	fmt.Println()
	fmt.Println("NETCAP Try Service - Upload and Analyze PCAP Files")
	fmt.Println("===================================================")
	fmt.Println()
}

func printUsage() {
	printHeader()
	fmt.Println("Usage examples:")
	fmt.Println("  $ net try -http :7070")
	fmt.Println("  $ net try -http :7070 -data-dir /custom/path")
	fmt.Println("  $ net try -http :7070 -dpi=false")
	fmt.Println()
	fmt.Println("Note: DPI (Deep Packet Inspection) is enabled by default for all analyses.")
	fmt.Println()
	fs.PrintDefaults()
}
