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
	fmt.Printf("HTTP server will listen on: http://%s\n", flagHTTP)

	// Create service configuration
	serviceConfig := &webui.ServiceConfig{
		MaxFileSize:           flagServiceMaxFileSize,
		MaxAnalysisHour:       flagServiceMaxPerHour,
		SessionExpiry:         flagServiceExpiry,
		CleanupInterval:       flagServiceCleanup,
		MaxStorageBytes:       flagServiceMaxStorage,
		PreloadLargestN:       flagServicePreloadLargestN,
		EnforceMaxSizePreload: flagServiceEnforceMaxSizePreload,
	}

	// Set data directory from flag or use default
	if flagServiceDataDir != "" {
		serviceConfig.DataDir = flagServiceDataDir
	} else {
		serviceConfig.DataDir = webui.DefaultServiceConfig().DataDir
	}

	fmt.Printf("Data directory: %s\n", serviceConfig.DataDir)
	fmt.Printf("Max file size: %d bytes\n", serviceConfig.MaxFileSize)
	fmt.Printf("Max analyses per hour per IP: %d\n", serviceConfig.MaxAnalysisHour)
	fmt.Printf("Session expiry: %d minutes\n", serviceConfig.SessionExpiry)
	if serviceConfig.MaxStorageBytes == 0 {
		fmt.Printf("Max storage per IP: unlimited\n")
	} else {
		fmt.Printf("Max storage per IP: %d bytes (%.2f GB)\n", serviceConfig.MaxStorageBytes, float64(serviceConfig.MaxStorageBytes)/(1024*1024*1024))
	}
	if serviceConfig.PreloadLargestN > 0 {
		fmt.Printf("Preload largest N files: %d\n", serviceConfig.PreloadLargestN)
	} else {
		fmt.Printf("Preload largest N files: all\n")
	}
	fmt.Printf("Enforce max size for preloaded pcaps: %v\n", serviceConfig.EnforceMaxSizePreload)

	// Create runtime config with actual flag values
	runtimeConfig := &webui.RuntimeConfig{
		Compress:              flagCompress,
		Buffer:                flagBuffer,
		Workers:               flagWorkers,
		PacketBuffer:          flagPacketBuffer,
		MemBufSize:            flagMemBufferSize,
		Interface:             flagInterface,
		PromiscMode:           flagPromiscMode,
		SnapLen:               flagSnapLen,
		BaseLayer:             flagBaseLayer,
		DecodeOptions:         flagDecodeOptions,
		Payload:               flagPayload,
		Context:               flagContext,
		MacDB:                 flagMACDB,
		
		ServiceDB:             flagServiceDB,
		GeoDB:                 flagGeolocationDB,
		ReverseDNS:            flagReverseDNS,
		LocalDNS:              flagLocalDNS,
		ReassembleConnections: flagReassembleConnections,
		FlushEvery:            flagFlushevery,
		Checksum:              flagChecksum,
		NoOptCheck:            flagNooptcheck,
		IgnoreFSMErr:          flagIgnorefsmerr,
		AllowMissingInit:      flagAllowmissinginit,
		ModbusRTUEndpoints:    flagModbusRTUEndpoints,
		ClosePendingTimeout:   flagClosePendingTimeout,
		CloseInactiveTimeout:  flagCloseInactiveTimeout,
		Proto:                 flagProto,
		JSON:                  flagJSON,
		CSV:                   flagCSV,
		Elastic:               flagElastic,
		ElasticAddrs:          flagElasticAddrs,
		ElasticUser:           flagElasticUser,
		IgnoreUnknown:         flagIgnoreUnknown,
		FreeOSMemory:          flagFreeOSMemory,
		ConnFlushInterval:     flagConnFlushInterval,
		ConnTimeout:           flagConnTimeOut,
		FlowFlushInterval:     flagFlowFlushInterval,
		FlowTimeout:           flagFlowTimeOut,
		Entropy:               flagCalcEntropy,
		TCPDebug:              flagTCPDebug,
		SaveConns:             flagSaveConns,
		DefragIPv4:            flagDefragIPv4,
		HexDump:               flagHexdump,
		BannerSize:            flagBannerSize,
	}

	// Create unified server in service mode
	server := webui.NewServer(
		flagHTTP,
		serviceConfig.DataDir,
		nil,           // no input files in service mode
		"",            // no custom assets path
		false,         // debug logging
		flagDPI,       // DPI configuration
		true,          // isServiceMode = true
		serviceConfig, // service configuration
		runtimeConfig, // actual runtime configuration values
		flagDev,       // dev mode: use current binary for job execution
	)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	log.Println("[Service] Signal handler registered for SIGINT and SIGTERM")

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	fmt.Printf("\n%sWeb UI available at: http://%s%s\n\n", "\033[32m", flagHTTP, "\033[0m")
	log.Printf("[Service] Server started successfully, waiting for shutdown signal...")

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("[Service] Received signal: %v - initiating graceful shutdown", sig)
	fmt.Printf("\nReceived signal %v, shutting down gracefully...\n", sig)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	fmt.Println("Service mode stopped")
}
