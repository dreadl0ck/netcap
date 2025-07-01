# Fix Array Bounds Violations in TCP Overlap Detection

## Summary
The TCP overlap detection code contains multiple slice operations with potential negative indices that can cause runtime panics and memory corruption.

## Location
- **File**: `reassembly/assembler.go`
- **Lines**: 398, 403, 410 (in checkOverlap function)

## Problem Description
The overlap detection algorithm uses slice operations that can result in negative indices, causing runtime panics:

### Problematic Code:
```go
// Line 398 - Potential negative index
cur.bytes = cur.bytes[:-start.difference(cur.seq)]

// Line 403 - Another negative index scenario  
cur.bytes = cur.bytes[-end.difference(cur.seq):]

// Line 410 - Complex copy with potential negative indices
copy(cur.bytes[-diffStart:-diffStart+len(bytes)], bytes)
```

### Root Cause:
1. **Signed Arithmetic**: The `difference()` function returns signed integers
2. **Negative Slicing**: Using negative results as slice indices without validation
3. **No Bounds Checking**: Missing validation before slice operations
4. **Complex Logic**: The 6-case overlap detection makes it hard to trace execution paths

## Impact
- **Runtime Panics**: Application crashes when negative indices are used
- **Memory Corruption**: Invalid memory access could corrupt adjacent data
- **Data Loss**: Incorrect slicing could lose or corrupt packet data
- **Security Risk**: Potential for exploiting bounds violations

## Error Examples
```go
// If start.difference(cur.seq) returns positive value, this panics:
cur.bytes = cur.bytes[:-start.difference(cur.seq)]  // PANIC: negative index

// Similar issue with end differences:
cur.bytes = cur.bytes[-end.difference(cur.seq):]   // PANIC: negative index
```

## Proposed Solution

### 1. Add Bounds Checking Helper
```go
// Safe slice operation with bounds validation
func safeSlice(data []byte, start, end int) ([]byte, error) {
    if start < 0 || end < 0 || start > len(data) || end > len(data) || start > end {
        return nil, fmt.Errorf("invalid slice bounds: start=%d, end=%d, len=%d", start, end, len(data))
    }
    return data[start:end], nil
}
```

### 2. Validate Before Slicing
```go
// Instead of direct slicing:
cur.bytes = cur.bytes[:-start.difference(cur.seq)]

// Use safe validation:
diff := start.difference(cur.seq)
if diff > 0 && diff <= len(cur.bytes) {
    cur.bytes = cur.bytes[:len(cur.bytes)-diff]
} else {
    // Handle error case appropriately
    return fmt.Errorf("invalid slice operation: diff=%d, len=%d", diff, len(cur.bytes))
}
```

### 3. Refactor Overlap Detection
```go
// Break down complex overlap cases into smaller, testable functions
func handleOverlapCase1(cur *page, start, end Sequence, bytes []byte) error {
    // Clear, safe implementation with bounds checking
    // ...
}

func handleOverlapCase2(cur *page, start, end Sequence, bytes []byte) error {
    // Clear, safe implementation with bounds checking
    // ...
}
```

## Testing Requirements
- [ ] Unit tests for each overlap case with boundary conditions
- [ ] Negative index scenarios that currently cause panics
- [ ] Edge cases: empty slices, maximum length slices
- [ ] Fuzz testing with random sequence numbers and byte arrays
- [ ] Integration tests with real network packet sequences

## Files to Modify
- `reassembly/assembler.go` - Main overlap detection logic
- Add new utility functions for safe slice operations
- Update all slice operations in overlap handling

## Debugging Aids
Add logging to track which overlap case is being executed:
```go
func (a *Assembler) checkOverlap(/*...*/) error {
    debugf("Overlap detection: start=%d, end=%d, cur.seq=%d, case=%d", 
           start, end, cur.seq, caseNumber)
    // ... rest of function
}
```

## Priority
**High** - These are critical runtime safety issues that can crash the application.

## Related Issues
- Sequence number type issues (int64 vs uint32) contribute to incorrect arithmetic
- Complex overlap logic makes debugging difficult
- Memory management issues may be triggered by these bounds violations

## Acceptance Criteria
- [ ] All slice operations include bounds checking
- [ ] No runtime panics possible from negative indices
- [ ] Comprehensive test coverage for all overlap cases
- [ ] Clear error handling for invalid slice operations
- [ ] Performance impact is minimal (bounds checking overhead)