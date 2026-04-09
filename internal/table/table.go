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

// Package table provides simple ASCII table rendering for terminal output.
package table

import (
	"io"
	"strings"
)

// columnPadding defines extra space on each side of cell content.
const columnPadding = 1

// Render outputs a formatted ASCII table to the provided writer.
// The table displays headers as the first row followed by data rows.
// Each column width is determined by the longest content in that column.
func Render(w io.Writer, headers []string, data [][]string) {
	if len(headers) == 0 {
		return
	}

	// Determine maximum width needed for each column
	widths := computeColumnWidths(headers, data)

	// Build and write the table
	var output strings.Builder

	// Top border
	writeDivider(&output, widths)

	// Header row
	writeRow(&output, headers, widths)

	// Separator between header and data
	writeDivider(&output, widths)

	// Data rows
	for _, row := range data {
		writeRow(&output, row, widths)
	}

	// Bottom border
	writeDivider(&output, widths)

	_, _ = io.WriteString(w, output.String())
}

// computeColumnWidths calculates the required width for each column.
// Width is determined by the maximum length of content across header and all data rows.
func computeColumnWidths(headers []string, data [][]string) []int {
	numCols := len(headers)
	widths := make([]int, numCols)

	// Start with header widths
	for col, h := range headers {
		widths[col] = len(h)
	}

	// Check each data row for longer content
	for _, row := range data {
		for col := 0; col < numCols && col < len(row); col++ {
			cellLen := len(row[col])
			if cellLen > widths[col] {
				widths[col] = cellLen
			}
		}
	}

	// Add padding to each column
	for i := range widths {
		widths[i] += columnPadding * 2
	}

	return widths
}

// writeDivider outputs a horizontal line using dashes.
func writeDivider(b *strings.Builder, widths []int) {
	b.WriteByte('+')
	for _, w := range widths {
		for range w {
			b.WriteByte('-')
		}
		b.WriteByte('+')
	}
	b.WriteByte('\n')
}

// writeRow outputs a single row with cell content padded appropriately.
func writeRow(b *strings.Builder, cells []string, widths []int) {
	b.WriteByte('|')
	for col, w := range widths {
		content := ""
		if col < len(cells) {
			content = cells[col]
		}

		// Calculate spacing needed
		contentWidth := w - (columnPadding * 2)
		padRight := max(contentWidth-len(content), 0)

		// Write padding + content + remaining padding
		b.WriteByte(' ')
		b.WriteString(content)
		for i := 0; i < padRight+columnPadding; i++ {
			b.WriteByte(' ')
		}
		b.WriteByte('|')
	}
	b.WriteByte('\n')
}
