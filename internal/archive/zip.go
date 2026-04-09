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

// Package archive provides utilities for working with compressed archives.
package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractZip decompresses a ZIP archive to the specified destination directory.
// Returns a list of extracted file paths and any error encountered.
func ExtractZip(archivePath, destDir string) ([]string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip archive: %w", err)
	}
	defer reader.Close()

	var extractedFiles []string

	for _, entry := range reader.File {
		outputPath, err := sanitizePath(destDir, entry.Name)
		if err != nil {
			return extractedFiles, err
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(outputPath, 0755); err != nil {
				return extractedFiles, fmt.Errorf("failed to create directory %s: %w", outputPath, err)
			}
			continue
		}

		// Ensure parent directory exists
		parentDir := filepath.Dir(outputPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return extractedFiles, fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
		}

		if err := extractSingleFile(entry, outputPath); err != nil {
			return extractedFiles, err
		}

		extractedFiles = append(extractedFiles, outputPath)
	}

	return extractedFiles, nil
}

// sanitizePath ensures the output path is within the destination directory
// to prevent zip slip vulnerabilities.
func sanitizePath(destDir, entryName string) (string, error) {
	cleanPath := filepath.Join(destDir, entryName)

	// Verify the path is within destination directory
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve destination path: %w", err)
	}

	absCleanPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve output path: %w", err)
	}

	if !strings.HasPrefix(absCleanPath, absDestDir+string(os.PathSeparator)) && absCleanPath != absDestDir {
		return "", fmt.Errorf("invalid file path in archive: %s", entryName)
	}

	return cleanPath, nil
}

// extractSingleFile extracts one file from the archive to the specified path.
func extractSingleFile(entry *zip.File, outputPath string) error {
	source, err := entry.Open()
	if err != nil {
		return fmt.Errorf("failed to open archive entry %s: %w", entry.Name, err)
	}
	defer source.Close()

	dest, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, entry.Mode())
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return fmt.Errorf("failed to extract %s: %w", entry.Name, err)
	}

	return nil
}

