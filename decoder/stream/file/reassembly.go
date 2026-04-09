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

package file

import (
	"errors"
	"slices"
)

// FileReassembler handles reassembly of files that may arrive out-of-order
// or with missing chunks (e.g., due to packet loss)
type FileReassembler struct {
	chunks       map[int64][]byte // offset -> data
	totalSize    int64
	seenBytes    int64
	missingBytes int64
}

// NewFileReassembler creates a new file reassembler
func NewFileReassembler(totalSize int64) *FileReassembler {
	return &FileReassembler{
		chunks:    make(map[int64][]byte),
		totalSize: totalSize,
	}
}

// AddChunk adds a chunk of data at the specified offset
func (fr *FileReassembler) AddChunk(offset int64, data []byte) {
	if len(data) == 0 {
		return
	}

	// Store the chunk
	fr.chunks[offset] = data
	fr.seenBytes += int64(len(data))
}

// IsComplete checks if all bytes have been received and are contiguous
func (fr *FileReassembler) IsComplete() bool {
	if fr.totalSize > 0 && fr.seenBytes < fr.totalSize {
		return false
	}
	return fr.hasContiguousData()
}

// hasContiguousData checks if the chunks form a contiguous stream
func (fr *FileReassembler) hasContiguousData() bool {
	if len(fr.chunks) == 0 {
		return false
	}

	// Get sorted offsets
	offsets := make([]int64, 0, len(fr.chunks))
	for offset := range fr.chunks {
		offsets = append(offsets, offset)
	}
	slices.Sort(offsets)

	// Check if data starts at 0
	if offsets[0] != 0 {
		return false
	}

	// Check for gaps
	expectedOffset := int64(0)
	for _, offset := range offsets {
		if offset > expectedOffset {
			// Gap detected
			return false
		}
		expectedOffset = offset + int64(len(fr.chunks[offset]))
	}

	return true
}

// Reassemble reconstructs the file from chunks
// If includeMissing is false, the function returns an error if data is missing
// If includeMissing is true, gaps will be filled with zeros (sparse file)
func (fr *FileReassembler) Reassemble(includeMissing bool) ([]byte, error) {
	if len(fr.chunks) == 0 {
		return nil, errors.New("no chunks to reassemble")
	}

	// Get sorted offsets
	offsets := make([]int64, 0, len(fr.chunks))
	for offset := range fr.chunks {
		offsets = append(offsets, offset)
	}
	slices.Sort(offsets)

	// Determine total size from chunks if not specified
	size := fr.totalSize
	if size == 0 {
		// Calculate from chunks - find the rightmost byte
		lastOffset := offsets[len(offsets)-1]
		size = lastOffset + int64(len(fr.chunks[lastOffset]))
	}

	result := make([]byte, size)
	currentPos := int64(0)
	fr.missingBytes = 0

	for _, offset := range offsets {
		chunk := fr.chunks[offset]

		// Check for gap before this chunk
		if offset > currentPos {
			gap := offset - currentPos
			fr.missingBytes += gap
			if !includeMissing {
				return nil, errors.New("missing bytes in file reassembly")
			}
			// Leave gap as zeros (sparse file)
			currentPos = offset
		}

		// Handle overlapping chunks - current chunk starts before current position
		if offset < currentPos {
			// Skip the overlapping part
			skipBytes := currentPos - offset
			if skipBytes >= int64(len(chunk)) {
				// Entire chunk is overlapped, skip it
				continue
			}
			// Copy only the non-overlapping part
			copy(result[currentPos:], chunk[skipBytes:])
			currentPos += int64(len(chunk)) - skipBytes
		} else {
			// No overlap, copy entire chunk
			copy(result[offset:], chunk)
			currentPos = offset + int64(len(chunk))
		}
	}

	// Check if we're missing data at the end
	if currentPos < size {
		fr.missingBytes += (size - currentPos)
		if !includeMissing {
			return nil, errors.New("incomplete file data")
		}
	}

	return result, nil
}

// GetMissingBytes returns the number of missing bytes
func (fr *FileReassembler) GetMissingBytes() int64 {
	return fr.missingBytes
}

// GetSeenBytes returns the number of bytes received
func (fr *FileReassembler) GetSeenBytes() int64 {
	return fr.seenBytes
}
