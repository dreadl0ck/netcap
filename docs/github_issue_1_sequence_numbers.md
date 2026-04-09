# Fix TCP Sequence Number Type Inconsistency

## Summary
The TCP reassembly implementation uses `int64` for sequence numbers instead of the RFC-mandated `uint32`, causing wraparound vulnerabilities and RFC non-compliance.

## Location
- **File**: `reassembly/sequence.go:12`
- **Code**: `type Sequence int64`

## Problem Description
TCP RFC 793/9293 specifies that sequence numbers must be 32-bit unsigned integers (0 to 4,294,967,295). The current implementation uses `int64`, which creates several critical issues:

### Issues:
1. **Wraparound Vulnerabilities**: Mixing signed/unsigned arithmetic leads to incorrect sequence comparisons
2. **Integer Overflow**: Operations may overflow unexpectedly due to signed arithmetic  
3. **RFC Non-compliance**: Violates TCP specification requirements
4. **Cross-platform Inconsistencies**: Different behavior on different architectures

### Example Problem:
```go
// Current problematic implementation
type Sequence int64

// Wraparound logic treats int64 as uint32, causing confusion
func (s Sequence) difference(t Sequence) int {
    if s > uint32Max-uint32Max/4 && t < uint32Max/4 {
        t += uint32Max  // Adding to int64 treated as uint32
    }
    return int(t - s)
}
```

## Impact
- **Security**: Potential sequence number prediction attacks
- **Reliability**: Incorrect packet ordering and data corruption
- **Performance**: Unnecessary 64-bit arithmetic overhead
- **Compliance**: Violates TCP RFC specifications

## Proposed Solution

### 1. Change Sequence Type
```go
// Change from int64 to uint32
type Sequence uint32
```

### 2. Update Arithmetic Logic
```go
// Proper uint32 wraparound handling
func (s Sequence) difference(t Sequence) int32 {
    return int32(t - s)  // Natural uint32 wraparound arithmetic
}
```

### 3. Update All Related Functions
- Update sequence comparison functions
- Fix arithmetic operations throughout the codebase
- Ensure proper wraparound handling

## Testing Requirements
- [ ] Unit tests for sequence number wraparound scenarios
- [ ] Test boundary conditions (0, maxUint32-1, maxUint32)
- [ ] Verify correct behavior across sequence number wraparound
- [ ] Test with real network captures containing wraparound

## Files to Modify
- `reassembly/sequence.go` - Core sequence type definition
- `reassembly/halfconnection.go` - Sequence tracking logic
- `reassembly/assembler.go` - Overlap detection using sequences
- Any other files using Sequence type

## Priority
**Critical** - This is a fundamental RFC compliance issue affecting data integrity.

## Related Issues
- Array bounds violations in overlap detection depend on sequence arithmetic
- Memory management issues may be exacerbated by incorrect sequence handling