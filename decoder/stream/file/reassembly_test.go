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

package file

import (
	"testing"
)

func TestFileReassembly_InOrder(t *testing.T) {
	fr := NewFileReassembler(21) // Exact size of data we're adding

	// Add chunks in order
	fr.AddChunk(0, []byte("Hello, "))
	fr.AddChunk(7, []byte("World!"))
	fr.AddChunk(13, []byte(" Testing"))

	if !fr.IsComplete() {
		t.Error("File should be complete")
	}

	data, err := fr.Reassemble(false)
	if err != nil {
		t.Fatalf("Reassembly failed: %v", err)
	}

	expected := "Hello, World! Testing"
	if string(data) != expected {
		t.Errorf("Reassembled data = %q, want %q", string(data), expected)
	}
}

func TestFileReassembly_OutOfOrder(t *testing.T) {
	fr := NewFileReassembler(16) // Exact size: "Hello, " (7) + gap (3) + "World!" (6) = 16

	// Add chunks out of order
	fr.AddChunk(10, []byte("World!"))
	fr.AddChunk(0, []byte("Hello, "))

	// There's a gap from 7-10, so not complete
	if fr.IsComplete() {
		t.Error("File should not be complete (has gap)")
	}

	// Allow sparse file
	data, err := fr.Reassemble(true)
	if err != nil {
		t.Fatalf("Reassembly failed: %v", err)
	}

	// Check individual chunks
	if string(data[0:7]) != "Hello, " {
		t.Errorf("First chunk = %q, want %q", string(data[0:7]), "Hello, ")
	}
	if string(data[10:16]) != "World!" {
		t.Errorf("Second chunk = %q, want %q", string(data[10:16]), "World!")
	}
	// Gap should be zeros
	if data[7] != 0 || data[8] != 0 || data[9] != 0 {
		t.Error("Gap should contain zeros")
	}
}

func TestFileReassembly_WithGaps(t *testing.T) {
	fr := NewFileReassembler(21) // "Hello, " (7) + gap (8) + "World!" (6) = 21

	// Add chunks with a gap
	fr.AddChunk(0, []byte("Hello, "))
	fr.AddChunk(15, []byte("World!")) // Gap from 7 to 15

	if fr.IsComplete() {
		t.Error("File should not be complete (has gap)")
	}

	// Try reassembly without allowing missing bytes
	_, err := fr.Reassemble(false)
	if err == nil {
		t.Error("Expected error for incomplete reassembly")
	}

	// Try reassembly with sparse file support
	data, err := fr.Reassemble(true)
	if err != nil {
		t.Fatalf("Sparse reassembly failed: %v", err)
	}

	if fr.GetMissingBytes() != 8 {
		t.Errorf("Missing bytes = %d, want 8", fr.GetMissingBytes())
	}

	// Verify the chunks we do have are correct
	if string(data[0:7]) != "Hello, " {
		t.Errorf("First chunk incorrect: %q", string(data[0:7]))
	}
	if string(data[15:21]) != "World!" {
		t.Errorf("Second chunk incorrect: %q", string(data[15:21]))
	}
}

func TestFileReassembly_EmptyChunks(t *testing.T) {
	fr := NewFileReassembler(10)

	// Add empty chunk
	fr.AddChunk(0, []byte{})

	if fr.GetSeenBytes() != 0 {
		t.Errorf("Seen bytes = %d, want 0", fr.GetSeenBytes())
	}

	// Add real data
	fr.AddChunk(0, []byte("Test"))

	if fr.GetSeenBytes() != 4 {
		t.Errorf("Seen bytes = %d, want 4", fr.GetSeenBytes())
	}
}

func TestFileReassembly_OverlappingChunks(t *testing.T) {
	fr := NewFileReassembler(10) // Exact size needed

	// Add overlapping chunks (first write wins - later duplicates are ignored)
	fr.AddChunk(0, []byte("AAAAAAAAAA"))
	fr.AddChunk(5, []byte("BBBBB")) // This overlaps with first chunk, will be ignored

	data, err := fr.Reassemble(false)
	if err != nil {
		t.Fatalf("Reassembly failed: %v", err)
	}

	// All bytes should be 'A' since the second chunk was completely overlapped
	expected := "AAAAAAAAAA"
	if string(data) != expected {
		t.Errorf("Data = %q, want %q (overlapped chunk should be ignored)", string(data), expected)
	}

	// Test reverse order - add smaller chunk first
	fr2 := NewFileReassembler(10)
	fr2.AddChunk(5, []byte("BBBBB"))
	fr2.AddChunk(0, []byte("AAAAAAAAAA"))

	data2, err := fr2.Reassemble(false)
	if err != nil {
		t.Fatalf("Reassembly failed: %v", err)
	}

	// First chunk (at offset 5) sets bytes 5-9 to 'B'
	// Second chunk (at offset 0) sets bytes 0-9, but 5-9 already set, so only 0-4 get written? No...
	// Actually with my logic, the second chunk would copy 10 bytes starting at offset 0
	// So it overwrites positions 5-9 that were set by the first chunk
	// Result should be all 'A'
	if string(data2) != "AAAAAAAAAA" {
		t.Errorf("Data2 = %q, want all A's", string(data2))
	}
}

func BenchmarkFileReassembly(b *testing.B) {
	// Create chunks
	chunks := make([][]byte, 10)
	for i := range chunks {
		chunks[i] = make([]byte, 1024)
		for j := range chunks[i] {
			chunks[i][j] = byte(i)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fr := NewFileReassembler(10240)

		// Add chunks in reverse order
		for j := len(chunks) - 1; j >= 0; j-- {
			fr.AddChunk(int64(j*1024), chunks[j])
		}

		fr.Reassemble(false)
	}
}
