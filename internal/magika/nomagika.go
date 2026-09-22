//go:build nomagika

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

// Package magika provides stubs when Magika support is disabled.
package magika

// Result holds the Magika classification result for a file.
type Result struct {
	Label       string
	MimeType    string
	Group       string
	Description string
	IsText      bool
}

// Init is a stub that does nothing when Magika is disabled.
func Init(assetsDir, modelName string) {}

// IsEnabled returns false when Magika is disabled.
func IsEnabled() bool {
	return false
}

// Classify is a stub that returns nil when Magika is disabled.
func Classify(filePath string) (*Result, error) {
	return nil, nil
}

// ClassifyBytes is a stub that returns nil when Magika is disabled.
func ClassifyBytes(data []byte) (*Result, error) {
	return nil, nil
}

// Destroy is a stub that does nothing when Magika is disabled.
func Destroy() {}
