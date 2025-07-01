# Simplify Complex TCP Overlap Detection Logic

## Summary
The TCP overlap detection algorithm in `checkOverlap()` is overly complex with 6 different cases, making it difficult to maintain, debug, and verify correctness.

## Location
- **File**: `reassembly/assembler.go`
- **Function**: `checkOverlap()` (lines 321-460)

## Problem Description
The current overlap detection implementation handles overlapping TCP segments using a complex algorithm with 6 distinct cases. This complexity creates several issues:

### Current Issues:
1. **Maintainability**: Complex nested conditions make code changes risky
2. **Debuggability**: Difficult to determine which case is executing during failures
3. **Testability**: Hard to achieve comprehensive test coverage for all branches
4. **Correctness**: Complex logic increases likelihood of edge case bugs
5. **Performance**: Inefficient case-by-case checking

### Code Complexity Example:
```go
func (a *Assembler) checkOverlap(/* ... */) {
    // Case 1: Complete overlap
    if start.difference(cur.seq) <= 0 && end.difference(cur.seq+Sequence(len(cur.bytes))) >= 0 {
        // Complex logic...
    }
    // Case 2: Partial overlap (beginning)
    else if start.difference(cur.seq) <= 0 && end.difference(cur.seq) > 0 {
        // More complex logic with potential bounds issues...
        cur.bytes = cur.bytes[:-start.difference(cur.seq)]  // POTENTIAL PANIC
    }
    // ... 4 more similarly complex cases
}
```

## Impact
- **Bug Risk**: Complex logic increases probability of edge case failures
- **Development Velocity**: Changes are slow and risky due to complexity
- **Testing Difficulty**: Hard to achieve full test coverage
- **Production Issues**: Difficult to debug overlap-related problems in production

## Proposed Solution

### 1. Decompose into Smaller Functions
```go
// Clear, single-responsibility functions
func (a *Assembler) handleCompleteOverlap(cur *page, start, end Sequence, bytes []byte) error {
    // Simple, focused logic for complete overlap case
    // Comprehensive bounds checking
    // Clear error handling
}

func (a *Assembler) handlePartialOverlapStart(cur *page, start, end Sequence, bytes []byte) error {
    // Simple, focused logic for partial overlap at start
    // Safe slice operations with validation
}

func (a *Assembler) handlePartialOverlapEnd(cur *page, start, end Sequence, bytes []byte) error {
    // Simple, focused logic for partial overlap at end
}

func (a *Assembler) handleNoOverlap(cur *page, start, end Sequence, bytes []byte) error {
    // Simple insertion logic for non-overlapping segments
}
```

### 2. Implement Clear Case Detection
```go
type OverlapType int

const (
    NoOverlap OverlapType = iota
    CompleteOverlap
    PartialOverlapStart
    PartialOverlapEnd
    CompletelyContained
    CompletelyContains
)

func (a *Assembler) detectOverlapType(cur *page, start, end Sequence) OverlapType {
    curStart := cur.seq
    curEnd := cur.seq + Sequence(len(cur.bytes))
    
    // Clear, readable overlap detection logic
    if end <= curStart || start >= curEnd {
        return NoOverlap
    }
    
    if start <= curStart && end >= curEnd {
        return CompleteOverlap
    }
    
    // ... other clear cases
}
```

### 3. Main Simplified Logic
```go
func (a *Assembler) checkOverlap(/* ... */) error {
    overlapType := a.detectOverlapType(cur, start, end)
    
    switch overlapType {
    case NoOverlap:
        return a.handleNoOverlap(cur, start, end, bytes)
    case CompleteOverlap:
        return a.handleCompleteOverlap(cur, start, end, bytes)
    case PartialOverlapStart:
        return a.handlePartialOverlapStart(cur, start, end, bytes)
    case PartialOverlapEnd:
        return a.handlePartialOverlapEnd(cur, start, end, bytes)
    // ... other cases
    default:
        return fmt.Errorf("unknown overlap type: %v", overlapType)
    }
}
```

## Benefits of Refactoring

### 1. Improved Maintainability
- Each function has single responsibility
- Changes isolated to specific overlap types
- Easier to understand and modify

### 2. Better Testability
- Unit tests for each overlap handler function
- Clear test cases for each overlap type
- Easier to achieve 100% test coverage

### 3. Enhanced Debuggability
- Clear logging of which case is being handled
- Easier to reproduce and fix specific overlap scenarios
- Better error messages with context

### 4. Improved Safety
- Bounds checking isolated to individual functions
- Clearer validation logic
- Explicit error handling for each case

## Testing Strategy

### 1. Unit Tests for Each Function
```go
func TestHandleCompleteOverlap(t *testing.T) {
    // Test cases for complete overlap scenarios
    // Boundary conditions
    // Error cases
}

func TestDetectOverlapType(t *testing.T) {
    // Test all overlap type detection
    // Edge cases and boundary conditions
}
```

### 2. Integration Tests
- Real packet sequences with various overlap patterns
- Performance comparison with current implementation
- Stress testing with high overlap scenarios

### 3. Visualization Tools
- Add debug output showing overlap detection decisions
- Visual representation of segment overlaps for debugging

## Implementation Plan

### Phase 1: Refactor Detection Logic
- [ ] Implement `detectOverlapType()` function
- [ ] Add comprehensive unit tests
- [ ] Validate against existing test cases

### Phase 2: Implement Handler Functions
- [ ] Create individual overlap handler functions
- [ ] Add bounds checking and error handling
- [ ] Unit test each handler independently

### Phase 3: Integration and Testing
- [ ] Replace complex `checkOverlap()` with new implementation
- [ ] Run comprehensive integration tests
- [ ] Performance benchmarking
- [ ] Documentation updates

## Files to Modify
- `reassembly/assembler.go` - Main overlap detection logic
- Add new test files for overlap detection
- Update documentation and comments

## Performance Considerations
- New implementation should be at least as fast as current version
- Benchmark with realistic network traffic patterns
- Consider caching overlap type detection results if beneficial

## Priority
**Medium-High** - Improves code quality and reduces bug risk, but not immediately critical.

## Related Issues
- Array bounds violations are easier to fix with simplified logic
- Sequence number type fixes will simplify overlap arithmetic
- Better error handling becomes possible with clearer code structure

## Acceptance Criteria
- [ ] All overlap cases handled by separate, focused functions
- [ ] 100% test coverage for overlap detection logic
- [ ] Performance equal to or better than current implementation
- [ ] Clear documentation of each overlap scenario
- [ ] No regression in existing functionality