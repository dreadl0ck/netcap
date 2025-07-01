# Improve TCP RFC Compliance

## Summary
The TCP reassembly implementation is missing several features required by TCP RFC 9293 (and RFC 793), including proper urgent pointer handling, Maximum Segment Lifetime (MSL) validation, and complete TCP state machine implementation.

## Location
- **Files**: Throughout `reassembly/` directory
- **Key Issues**: Missing TCP features, incomplete state machine, sequence number violations

## Problem Description

### Current RFC Compliance Issues:

#### 1. Missing Urgent Pointer Handling
**RFC Requirement**: RFC 9293 Section 3.1 specifies handling of urgent data via the urgent pointer.
**Current State**: No explicit handling of TCP urgent data in the reassembly logic.

```go
// Missing: Urgent pointer processing
type TCPHeader struct {
    // ... other fields
    // Missing: UrgentPointer field and handling
}
```

**Impact**: 
- Applications relying on urgent data (like telnet interrupt signals) may not work correctly
- Potential security issues if urgent data contains control information

#### 2. Maximum Segment Lifetime (MSL) Validation
**RFC Requirement**: RFC 9293 Section 3.9 specifies MSL handling for connection cleanup.
**Current State**: No validation for MSL requirements in connection management.

```go
// Missing: MSL-based connection cleanup
type connection struct {
    // Missing: lastActivity time.Time
    // Missing: MSL validation
}
```

**Impact**:
- Connections may persist longer than RFC-mandated timeouts
- Resource exhaustion from stale connections
- Potential for sequence number conflicts

#### 3. Incomplete TCP State Machine
**RFC Requirement**: RFC 9293 Section 3.2 defines complete TCP state transitions.
**Current State**: Simplified state tracking without full RFC compliance.

**Missing States/Transitions**:
- LISTEN state handling
- SYN-SENT state management  
- FIN-WAIT-1, FIN-WAIT-2 state transitions
- TIME-WAIT state with proper 2MSL timeout
- LAST-ACK state handling

#### 4. Insufficient Duplicate Segment Handling
**RFC Requirement**: RFC 9293 Section 3.4 specifies duplicate segment processing.
**Current State**: Basic overlap detection without comprehensive duplicate handling.

**Issues**:
- Duplicate ACKs not properly tracked
- Retransmitted segments not optimally handled
- Fast retransmit detection missing

#### 5. Sequence Number Arithmetic Violations
**RFC Requirement**: RFC 9293 Section 3.3 specifies 32-bit unsigned sequence numbers.
**Current State**: Using `int64` instead of `uint32` (covered in separate issue).

### Missing TCP Features:

#### 1. Window Scaling (RFC 7323)
```go
// Missing: Window scaling option support
type TCPOptions struct {
    // Missing: WindowScale option
    // Missing: Timestamp option  
    // Missing: SACK option
}
```

#### 2. Selective Acknowledgment (SACK) - RFC 2018
- No support for SACK option parsing
- Missing SACK-based retransmission detection
- Inefficient reassembly without SACK information

#### 3. TCP Timestamps (RFC 7323)
- No timestamp option processing
- Missing RTT measurement capabilities
- No PAWS (Protection Against Wrapped Sequences) support

## Proposed Solutions

### 1. Implement Urgent Pointer Handling
```go
type TCPHeader struct {
    // ... existing fields
    UrgentPointer uint16
    Flags         TCPFlags
}

type TCPFlags struct {
    URG bool  // Urgent pointer field significant
    ACK bool  // Acknowledgment field significant
    PSH bool  // Push function
    RST bool  // Reset the connection
    SYN bool  // Synchronize sequence numbers
    FIN bool  // No more data from sender
}

func (a *Assembler) handleUrgentData(packet *TCPPacket) error {
    if packet.Header.Flags.URG {
        urgentEnd := packet.Header.Sequence + Sequence(packet.Header.UrgentPointer)
        // Mark urgent data range
        return a.markUrgentData(packet.Header.Sequence, urgentEnd, packet.Payload)
    }
    return nil
}
```

### 2. Add MSL-Based Connection Management
```go
type connection struct {
    // ... existing fields
    state        TCPState
    lastActivity time.Time
    mslTimeout   time.Duration  // Configurable MSL (default 2 minutes)
}

const (
    DefaultMSL = 2 * time.Minute  // RFC 9293 recommendation
)

func (c *connection) updateActivity() {
    c.lastActivity = time.Now()
}

func (c *connection) isExpired() bool {
    switch c.state {
    case TIME_WAIT:
        return time.Since(c.lastActivity) > 2*c.mslTimeout  // 2MSL for TIME_WAIT
    default:
        return time.Since(c.lastActivity) > c.mslTimeout
    }
}
```

### 3. Implement Complete TCP State Machine
```go
type TCPState int

const (
    CLOSED TCPState = iota
    LISTEN
    SYN_SENT
    SYN_RECEIVED
    ESTABLISHED
    FIN_WAIT_1
    FIN_WAIT_2
    CLOSE_WAIT
    CLOSING
    LAST_ACK
    TIME_WAIT
)

type StateMachine struct {
    currentState TCPState
    transitions  map[TCPState]map[TCPEvent]TCPState
}

func (sm *StateMachine) processEvent(event TCPEvent, packet *TCPPacket) (TCPState, error) {
    if nextStates, ok := sm.transitions[sm.currentState]; ok {
        if nextState, ok := nextStates[event]; ok {
            sm.currentState = nextState
            return nextState, nil
        }
    }
    return sm.currentState, fmt.Errorf("invalid transition from %v on event %v", sm.currentState, event)
}
```

### 4. Enhanced Duplicate Detection
```go
type DuplicateTracker struct {
    recentSegments map[Sequence]*SegmentInfo
    cleanupTime    time.Time
}

type SegmentInfo struct {
    sequence    Sequence
    length      int
    timestamp   time.Time
    retransmits int
}

func (dt *DuplicateTracker) isDuplicate(seq Sequence, length int) bool {
    key := seq
    if info, exists := dt.recentSegments[key]; exists {
        if info.length == length {
            info.retransmits++
            info.timestamp = time.Now()
            return true
        }
    }
    
    // Store new segment info
    dt.recentSegments[key] = &SegmentInfo{
        sequence:  seq,
        length:    length,
        timestamp: time.Now(),
    }
    return false
}
```

### 5. TCP Options Support
```go
type TCPOptions struct {
    WindowScale  *uint8     // RFC 7323
    Timestamp    *TCPTimestamp  // RFC 7323
    SACK         []SACKBlock    // RFC 2018
    MSS          *uint16    // RFC 793
}

type TCPTimestamp struct {
    TSval uint32  // Timestamp value
    TSecr uint32  // Timestamp echo reply
}

type SACKBlock struct {
    Start Sequence  // Left edge of block
    End   Sequence  // Right edge of block
}

func (a *Assembler) parseOptions(optData []byte) (*TCPOptions, error) {
    opts := &TCPOptions{}
    
    for len(optData) > 0 {
        if len(optData) < 2 {
            break
        }
        
        optType := optData[0]
        optLen := optData[1]
        
        switch optType {
        case 3: // Window Scale
            if optLen == 3 && len(optData) >= 3 {
                scale := optData[2]
                opts.WindowScale = &scale
            }
        case 8: // Timestamp
            if optLen == 10 && len(optData) >= 10 {
                tsval := binary.BigEndian.Uint32(optData[2:6])
                tsecr := binary.BigEndian.Uint32(optData[6:10])
                opts.Timestamp = &TCPTimestamp{TSval: tsval, TSecr: tsecr}
            }
        case 5: // SACK
            // Parse SACK blocks
            opts.SACK = parseSACKBlocks(optData[2:optLen])
        }
        
        optData = optData[optLen:]
    }
    
    return opts, nil
}
```

## Implementation Plan

### Phase 1: Basic RFC Compliance
- [ ] Implement TCP state machine with all states
- [ ] Add urgent pointer handling
- [ ] Implement MSL-based connection cleanup
- [ ] Add proper duplicate segment detection

### Phase 2: Enhanced Features
- [ ] Add TCP options parsing (Window Scale, Timestamps, SACK)
- [ ] Implement PAWS protection
- [ ] Add fast retransmit detection
- [ ] Implement proper connection establishment/teardown

### Phase 3: Advanced Features
- [ ] Add congestion control awareness
- [ ] Implement ECN (Explicit Congestion Notification) support
- [ ] Add TCP metrics collection per RFC requirements
- [ ] Implement proper error handling for malformed packets

### Phase 4: Testing and Validation
- [ ] Create comprehensive RFC compliance test suite
- [ ] Test against real network captures
- [ ] Validate against other TCP implementations
- [ ] Performance testing with new features

## Configuration Options
```go
type RFCConfig struct {
    EnableUrgentData     bool          `yaml:"enable_urgent_data"`
    MSLTimeout          time.Duration `yaml:"msl_timeout"`
    EnableWindowScaling bool          `yaml:"enable_window_scaling"`
    EnableTimestamps    bool          `yaml:"enable_timestamps"`
    EnableSACK          bool          `yaml:"enable_sack"`
    StrictRFCMode       bool          `yaml:"strict_rfc_mode"`
    
    // State machine timeouts
    SynTimeout          time.Duration `yaml:"syn_timeout"`
    FinTimeout          time.Duration `yaml:"fin_timeout"`
    TimeWaitTimeout     time.Duration `yaml:"time_wait_timeout"`
}
```

## Testing Requirements

### 1. RFC Compliance Tests
```go
func TestTCPStateMachine(t *testing.T) {
    // Test all valid state transitions
    // Test invalid transition rejection
    // Test timeout-based transitions
}

func TestUrgentDataHandling(t *testing.T) {
    // Test urgent pointer processing
    // Test urgent data extraction
    // Test boundary conditions
}

func TestMSLCompliance(t *testing.T) {
    // Test connection cleanup after MSL
    // Test TIME_WAIT state duration
    // Test resource cleanup
}
```

### 2. Interoperability Tests
- Test against Linux TCP stack
- Test against Windows TCP stack  
- Test against BSD TCP implementations
- Validate with network simulation tools

### 3. Performance Impact Tests
- Measure overhead of full state machine
- Benchmark option parsing performance
- Test memory usage with enhanced features

## Files to Modify
- `reassembly/tcpassembly.go` - Add TCP options and state machine
- `reassembly/connection.go` - Enhance with full state tracking
- `reassembly/assembler.go` - Add urgent data and duplicate handling
- Add new files:
  - `reassembly/tcp_state.go` - State machine implementation
  - `reassembly/tcp_options.go` - Options parsing
  - `reassembly/rfc_compliance.go` - RFC validation utilities

## Documentation Requirements
- Document which RFC features are supported
- Provide configuration guide for RFC compliance
- Add troubleshooting guide for common TCP issues
- Create migration guide from current implementation

## Priority
**Medium** - Important for correctness and interoperability, but not immediately critical for basic functionality.

## Related Issues
- Sequence number type fixes are prerequisite for proper RFC compliance
- Memory management improvements needed for option storage
- Concurrency fixes required for thread-safe state management

## Acceptance Criteria
- [ ] Full TCP state machine implementation per RFC 9293
- [ ] Urgent pointer handling for urgent data
- [ ] MSL-based connection lifecycle management
- [ ] TCP options parsing (Window Scale, Timestamps, SACK)
- [ ] Comprehensive duplicate segment detection
- [ ] Configurable RFC compliance levels
- [ ] No regression in performance for basic use cases
- [ ] Interoperability with major TCP implementations
- [ ] Complete test coverage for all RFC features