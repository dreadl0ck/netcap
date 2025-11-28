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

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// AlertWriter is an interface for writing alerts.
type AlertWriter interface {
	WriteAlert(alert *types.Alert) error
	Close() error
}

// FileAlertWriter writes alerts to a netcap audit record file.
type FileAlertWriter struct {
	writer         netio.AuditRecordWriter
	mu             sync.Mutex
	appendMode     bool
	existingAlerts []*types.Alert
	newAlerts      []*types.Alert
	outputDir      string
}

// NewFileAlertWriter creates a new file-based alert writer.
// Alerts are written to Alert.ncap.gz in the specified output directory.
// If the file exists, it reads existing alerts and will rewrite them along with new ones on Close.
func NewFileAlertWriter(outputDir string) (*FileAlertWriter, error) {
	alertFile := filepath.Join(outputDir, "Alert.ncap.gz")

	writer := &FileAlertWriter{
		outputDir:      outputDir,
		existingAlerts: make([]*types.Alert, 0),
		newAlerts:      make([]*types.Alert, 0),
		appendMode:     false,
	}

	// Check if the alert file already exists
	if _, err := os.Stat(alertFile); err == nil {
		// File exists, read existing alerts
		writer.appendMode = true
		existingAlerts, err := readExistingAlerts(alertFile)
		if err != nil {
			// If we can't read existing alerts, log but continue (will overwrite)
			fmt.Printf("Warning: could not read existing alerts: %v\n", err)
		} else {
			writer.existingAlerts = existingAlerts
		}
	}

	return writer, nil
}

// readExistingAlerts reads all alerts from an existing alert file
func readExistingAlerts(filePath string) ([]*types.Alert, error) {
	alerts := make([]*types.Alert, 0)

	reader, err := netio.Open(filePath, defaults.BufferSize)
	if err != nil {
		return nil, fmt.Errorf("failed to open alerts file: %w", err)
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Read all existing alerts
	for {
		alert := &types.Alert{}
		err := reader.Next(alert)
		if err != nil {
			break
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// WriteAlert collects an alert to be written on Close.
func (w *FileAlertWriter) WriteAlert(alert *types.Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Just collect the alert, we'll write everything on Close
	w.newAlerts = append(w.newAlerts, alert)

	return nil
}

// Close writes all alerts (existing + new) to the alert file.
func (w *FileAlertWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// If no new alerts were generated, nothing to do
	if len(w.newAlerts) == 0 {
		return nil
	}

	// Create a new writer for the alert file
	writer := netio.NewAuditRecordWriter(&netio.WriterConfig{
		Name:                 "Alert",
		Proto:                true,
		Buffer:               true,
		Compress:             true,
		Out:                  w.outputDir,
		CompressionBlockSize: defaults.CompressionBlockSize,
		CompressionLevel:     defaults.CompressionLevel,
	})

	// Write the header first
	if err := writer.WriteHeader(types.Type_NC_Alert); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write all existing alerts first
	for _, alert := range w.existingAlerts {
		if err := writer.Write(alert); err != nil {
			return fmt.Errorf("failed to write existing alert: %w", err)
		}
	}

	// Write all new alerts
	for _, alert := range w.newAlerts {
		if err := writer.Write(alert); err != nil {
			return fmt.Errorf("failed to write new alert: %w", err)
		}
	}

	// Close the writer to flush all data
	totalAlerts := int64(len(w.existingAlerts) + len(w.newAlerts))
	_, _ = writer.Close(totalAlerts)

	return nil
}
