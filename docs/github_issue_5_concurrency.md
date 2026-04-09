# Fix Concurrency and Race Condition Issues

## Summary
The TCP reassembly implementation has several concurrency issues including race conditions, potential deadlocks, and inconsistent locking patterns that can lead to data corruption and crashes.

## Location
- **Files**: `reassembly/assembler.go`, `reassembly/stream_pool.go`, `reassembly/connection.go`
- **Key Issues**: Shared state access, multiple mutex usage, race conditions in buildSG()

## Problem Description

### Current Issues:

#### 1. Known Race Condition in Assembler
**Location**: `reassembly/assembler.go:181`
```go
// RACE comment indicates known race condition
a.Lock()
a.ret = a.ret[:0]  // Shared state modification without proper protection
a.Unlock()
```
- **Shared State**: The `ret` slice is accessed concurrently across goroutines
- **Insufficient Protection**: Current locking doesn't prevent all race conditions
- **Data Corruption**: Concurrent modifications can corrupt the return slice

#### 2. Complex Locking in buildSG()
**Location**: `reassembly/assembler.go:763`
```go
func (a *Assembler) buildSG(/* ... */) {
    // Complex nested locking pattern
    a.Lock()
    // ... complex logic with potential for deadlock
    if someCondition {
        // Additional locks acquired
        conn.Lock()
        // ... potential deadlock scenario
        conn.Unlock()
    }
    a.Unlock()
}
```
- **Nested Locking**: Multiple locks acquired in complex patterns
- **Deadlock Risk**: Different lock acquisition orders can cause deadlocks
- **Lock Contention**: Fine-grained locking causes performance issues

#### 3. StreamPool Concurrency Issues
**Location**: `reassembly/stream_pool.go`
```go
type StreamPool struct {
    // Multiple concurrent data structures without consistent protection
    connections map[string]*connection
    mu          sync.RWMutex
    // ... other fields
}
```
- **Inconsistent Protection**: Not all shared state properly protected
- **Reader-Writer Conflicts**: RWMutex usage not optimized for access patterns
- **Connection Lifecycle**: Race conditions in connection creation/deletion

#### 4. Connection State Management
**Location**: `reassembly/connection.go`
```go
type connection struct {
    // Multiple fields accessed concurrently
    closed    bool
    mu        sync.Mutex
    // ... potential for state inconsistencies
}
```
- **State Consistency**: Connection state can become inconsistent under load
- **Resource Cleanup**: Race conditions during connection cleanup
- **Bidirectional Races**: Races between up and down stream processing

## Impact
- **Data Races**: Memory corruption and unpredictable behavior
- **Deadlocks**: Application hanging under high concurrency
- **Performance**: Lock contention reducing throughput
- **Reliability**: Intermittent failures difficult to reproduce and debug

## Identified Race Conditions

### 1. Assembler ret Slice Race
```go
// Thread 1                    // Thread 2
a.Lock()                      a.Lock() // blocks
a.ret = a.ret[:0]            // waits
for _, p := range pages {     
    a.ret = append(a.ret, p)  
}                             
result := a.ret               
a.Unlock()                    a.ret = a.ret[:0] // corrupts Thread 1's result
                              a.Unlock()
```

### 2. Connection Pool Race
```go
// Thread 1: Adding connection    // Thread 2: Removing connection
pool.mu.Lock()                   pool.mu.Lock() // blocks
pool.connections[key] = conn     // waits  
pool.mu.Unlock()                 delete(pool.connections, key)
// continues using conn           pool.mu.Unlock()
conn.process()  // may use deleted connection
```

### 3. Page Buffer Race
```go
// Thread 1: Reading page        // Thread 2: Modifying page
page.mu.RLock()                 page.mu.Lock() // blocks
data := page.bytes              // waits
page.mu.RUnlock()               page.bytes = newBytes // concurrent modification
// uses potentially invalid data  page.mu.Unlock()
```

## Proposed Solutions

### 1. Fix Assembler Race Condition
```go
type Assembler struct {
    // Use per-goroutine storage instead of shared state
    retPool sync.Pool  // Pool of result slices
    // ... other fields
}

func (a *Assembler) getResult() []reassemblyObject {
    // Get per-goroutine result slice
    if v := a.retPool.Get(); v != nil {
        ret := v.([]reassemblyObject)
        return ret[:0]  // Reset length but keep capacity
    }
    return make([]reassemblyObject, 0, 16)
}

func (a *Assembler) releaseResult(ret []reassemblyObject) {
    if cap(ret) <= 64 {  // Prevent memory leaks from large slices
        a.retPool.Put(ret)
    }
}
```

### 2. Simplify Locking Strategy
```go
// Single, coarse-grained locking per assembler operation
func (a *Assembler) processPacket(packet *Packet) ([]reassemblyObject, error) {
    // Single lock for entire operation
    a.mu.Lock()
    defer a.mu.Unlock()
    
    // All processing under single lock - simpler but safer
    result := a.getResult()
    defer a.releaseResult(result)
    
    // Process without additional locking
    return a.doProcess(packet, result)
}
```

### 3. Atomic Operations for Simple State
```go
type connection struct {
    closed    int32  // Use atomic operations instead of mutex for simple flags
    lastSeen  int64  // Atomic timestamp
    mu        sync.RWMutex  // Only for complex state
    // ... other fields
}

func (c *connection) Close() {
    if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
        // Only first caller performs cleanup
        c.cleanup()
    }
}

func (c *connection) IsClosed() bool {
    return atomic.LoadInt32(&c.closed) != 0
}
```

### 4. Improved StreamPool Design
```go
type StreamPool struct {
    // Separate read-write maps for different access patterns
    activeConns   sync.Map  // Concurrent map for active connections
    
    // Separate cleanup mechanism
    cleanupMu     sync.Mutex
    cleanupNeeded []string
    
    // Statistics with atomic operations
    totalConns    int64
    activeCount   int64
}

func (sp *StreamPool) GetConnection(key string) (*connection, bool) {
    // No locking needed with sync.Map
    if v, ok := sp.activeConns.Load(key); ok {
        return v.(*connection), true
    }
    return nil, false
}

func (sp *StreamPool) AddConnection(key string, conn *connection) {
    sp.activeConns.Store(key, conn)
    atomic.AddInt64(&sp.activeCount, 1)
}
```

### 5. Lock-Free Page Management
```go
type page struct {
    // Immutable after creation - no locking needed
    buf      []byte
    seq      Sequence
    
    // Atomic reference counting for lifecycle
    refCount int32
}

func (p *page) addRef() {
    atomic.AddInt32(&p.refCount, 1)
}

func (p *page) release() bool {
    if atomic.AddInt32(&p.refCount, -1) == 0 {
        // Last reference - safe to cleanup
        return true
    }
    return false
}
```

## Implementation Plan

### Phase 1: Fix Critical Race Conditions
- [ ] Replace shared `ret` slice with per-goroutine storage
- [ ] Add atomic operations for simple state flags
- [ ] Fix connection pool race conditions

### Phase 2: Simplify Locking
- [ ] Reduce lock granularity to prevent deadlocks
- [ ] Replace fine-grained locks with coarser but safer alternatives
- [ ] Document lock ordering to prevent future deadlocks

### Phase 3: Optimize Performance
- [ ] Use lock-free data structures where possible
- [ ] Implement reference counting for page lifecycle
- [ ] Add concurrent-safe metrics collection

### Phase 4: Testing and Validation
- [ ] Add race detection tests
- [ ] Stress test under high concurrency
- [ ] Performance benchmarking

## Testing Strategy

### 1. Race Detection
```bash
# Enable race detector in tests
go test -race ./reassembly/...

# Stress testing with race detector
go test -race -count=100 -parallel=10 ./reassembly/...
```

### 2. Concurrency Stress Tests
```go
func TestConcurrentReassembly(t *testing.T) {
    assembler := NewAssembler()
    
    // Launch many goroutines processing packets concurrently
    const numGoroutines = 100
    const packetsPerGoroutine = 1000
    
    var wg sync.WaitGroup
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < packetsPerGoroutine; j++ {
                packet := generateTestPacket()
                assembler.ProcessPacket(packet)
            }
        }()
    }
    wg.Wait()
    
    // Verify no corruption occurred
    assembler.Validate()
}
```

### 3. Deadlock Detection
```go
func TestDeadlockPrevention(t *testing.T) {
    // Test scenarios that previously caused deadlocks
    // Use timeouts to detect hanging
    done := make(chan bool)
    go func() {
        // Operations that might deadlock
        testComplexLockingScenario()
        done <- true
    }()
    
    select {
    case <-done:
        // Success
    case <-time.After(5 * time.Second):
        t.Fatal("Test likely deadlocked")
    }
}
```

## Metrics and Monitoring
```go
type ConcurrencyMetrics struct {
    RaceConditionCount   int64  // Detected race conditions
    DeadlockCount       int64  // Detected deadlocks
    LockContentionTime  int64  // Time spent waiting for locks
    ActiveGoroutines    int64  // Current active goroutines
}
```

## Configuration Options
```go
type ConcurrencyConfig struct {
    MaxConcurrentStreams int    `yaml:"max_concurrent_streams"`
    LockTimeout         int    `yaml:"lock_timeout_ms"`
    EnableRaceDetection bool   `yaml:"enable_race_detection"`
    PerformanceMode     string `yaml:"performance_mode"`  // "safe" or "fast"
}
```

## Files to Modify
- `reassembly/assembler.go` - Fix ret slice race and locking
- `reassembly/stream_pool.go` - Improve connection pool concurrency
- `reassembly/connection.go` - Add atomic operations for state
- `reassembly/page.go` - Implement reference counting
- Add new test files for concurrency testing

## Backward Compatibility
- Maintain existing API surface
- Add configuration options for new concurrency modes
- Gradual migration path for existing users

## Priority
**High** - Race conditions can cause data corruption and crashes in production.

## Related Issues
- Memory management improvements needed for thread-safe operations
- Sequence number fixes will simplify concurrent arithmetic
- Overlap detection refactoring will reduce lock complexity

## Acceptance Criteria
- [ ] All race conditions identified by `go test -race` are fixed
- [ ] No deadlocks in stress testing scenarios
- [ ] Performance equal to or better than current implementation
- [ ] Thread-safe operations for all public APIs
- [ ] Comprehensive concurrency test suite
- [ ] Clear documentation of thread safety guarantees