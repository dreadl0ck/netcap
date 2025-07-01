# Improve TCP Reassembly Memory Management

## Summary
The TCP reassembly implementation has several memory management issues including fixed page sizes, potential memory leaks, and inefficient memory usage patterns.

## Location
- **Files**: `reassembly/page.go`, `reassembly/memory.go`, `reassembly/assembler.go`
- **Key Issues**: Fixed 1900-byte pages, growing page caches, no bounds checking

## Problem Description

### Current Issues:

#### 1. Fixed Page Size Problems
```go
const pageBytes = 1900  // Fixed size in page.go
```
- **Internal Fragmentation**: 1900-byte pages may not match actual packet sizes
- **Memory Waste**: Small packets waste significant memory in large pages
- **Inflexibility**: Cannot adapt to different network conditions or packet patterns

#### 2. Memory Leak Potential
```go
// In memory.go - pageCache grows but never shrinks
type pageCache struct {
    pages []*page
    cache chan *page
}
```
- **Growing Caches**: Page caches grow indefinitely but never shrink
- **No Resource Limits**: No upper bound on total memory usage
- **Poor Resource Management**: Resources not properly released under memory pressure

#### 3. Bounds Checking Deficiencies
```go
// In page.go - potential unsafe operations
p.bytes = p.buf[:0]  // Could access invalid memory if buf is nil
```
- **Missing Validation**: Buffer operations without bounds checking
- **Unsafe Operations**: Direct buffer manipulation without safety checks
- **Race Conditions**: Concurrent access to page buffers without proper synchronization

#### 4. Inefficient Memory Patterns
- **No Memory Pooling**: Frequent allocation/deallocation causes GC pressure
- **Large Object Heap**: Fixed large pages contribute to LOH pressure
- **Poor Locality**: Scattered page allocation hurts cache performance

## Impact
- **Memory Leaks**: Long-running processes may consume excessive memory
- **Performance Degradation**: GC pressure from frequent allocations
- **Resource Exhaustion**: No protection against memory exhaustion attacks
- **Poor Scalability**: Fixed sizes don't scale with traffic patterns

## Proposed Solutions

### 1. Dynamic Page Sizing
```go
// Adaptive page sizes based on traffic patterns
type DynamicPagePool struct {
    smallPages   *pagePool  // 256 bytes for small packets
    mediumPages  *pagePool  // 1500 bytes for standard MTU
    largePages   *pagePool  // 9000 bytes for jumbo frames
    
    stats        PageStats  // Track allocation patterns
}

func (dpp *DynamicPagePool) GetPage(size int) *page {
    switch {
    case size <= 256:
        return dpp.smallPages.Get()
    case size <= 1500:
        return dpp.mediumPages.Get()
    default:
        return dpp.largePages.Get()
    }
}
```

### 2. Memory Pool with Limits
```go
type BoundedPagePool struct {
    maxPages    int           // Maximum pages to cache
    maxMemory   int64         // Maximum memory to use
    currentMem  int64         // Current memory usage
    pages       chan *page    // Bounded channel for pages
    mutex       sync.RWMutex  // Protection for memory tracking
}

func (bpp *BoundedPagePool) Get() *page {
    select {
    case p := <-bpp.pages:
        return p  // Reuse existing page
    default:
        // Create new page only if under memory limit
        if bpp.withinMemoryLimit() {
            return bpp.createPage()
        }
        return nil  // Signal memory pressure
    }
}
```

### 3. Safe Buffer Operations
```go
// Safe buffer operations with bounds checking
func (p *page) safeResize(newSize int) error {
    if newSize < 0 || newSize > cap(p.buf) {
        return fmt.Errorf("invalid resize: size=%d, capacity=%d", newSize, cap(p.buf))
    }
    p.bytes = p.buf[:newSize]
    return nil
}

func (p *page) safeCopy(data []byte, offset int) error {
    if offset < 0 || offset+len(data) > cap(p.buf) {
        return fmt.Errorf("copy would exceed buffer bounds")
    }
    copy(p.buf[offset:], data)
    return nil
}
```

### 4. Memory Monitoring and Cleanup
```go
type MemoryMonitor struct {
    maxMemoryMB     int64
    cleanupInterval time.Duration
    pools           []*BoundedPagePool
}

func (mm *MemoryMonitor) startCleanup() {
    ticker := time.NewTicker(mm.cleanupInterval)
    go func() {
        for range ticker.C {
            mm.cleanupUnderPressure()
        }
    }()
}

func (mm *MemoryMonitor) cleanupUnderPressure() {
    if mm.memoryUsage() > mm.maxMemoryMB {
        // Aggressively cleanup page caches
        for _, pool := range mm.pools {
            pool.shrink(0.5)  // Shrink by 50%
        }
    }
}
```

## Implementation Plan

### Phase 1: Add Memory Monitoring
- [ ] Implement memory usage tracking
- [ ] Add configurable memory limits
- [ ] Create memory pressure detection

### Phase 2: Improve Page Management
- [ ] Add bounds checking to all buffer operations
- [ ] Implement safe resize and copy operations
- [ ] Add comprehensive error handling

### Phase 3: Dynamic Sizing
- [ ] Implement multiple page pool sizes
- [ ] Add traffic pattern analysis
- [ ] Create adaptive allocation logic

### Phase 4: Cleanup and Optimization
- [ ] Implement periodic memory cleanup
- [ ] Add memory pool shrinking under pressure
- [ ] Optimize for common allocation patterns

## Configuration Options
```go
type MemoryConfig struct {
    MaxTotalMemoryMB    int64  `yaml:"max_total_memory_mb"`
    MaxPagesPerPool     int    `yaml:"max_pages_per_pool"`
    CleanupIntervalSec  int    `yaml:"cleanup_interval_sec"`
    SmallPageBytes      int    `yaml:"small_page_bytes"`
    MediumPageBytes     int    `yaml:"medium_page_bytes"`
    LargePageBytes      int    `yaml:"large_page_bytes"`
    EnableAdaptiveSizing bool  `yaml:"enable_adaptive_sizing"`
}
```

## Testing Requirements
- [ ] Memory leak tests with long-running scenarios
- [ ] Performance tests comparing fixed vs dynamic sizing
- [ ] Stress tests under memory pressure
- [ ] Concurrent access tests for thread safety
- [ ] Memory usage profiling and benchmarks

## Metrics to Add
```go
type MemoryMetrics struct {
    TotalPagesAllocated   int64
    TotalMemoryUsed      int64
    PageCacheHitRate     float64
    MemoryPressureEvents int64
    CleanupOperations    int64
}
```

## Files to Modify
- `reassembly/page.go` - Add safe buffer operations
- `reassembly/memory.go` - Implement bounded pools and monitoring
- `reassembly/assembler.go` - Update to use new memory management
- Add new configuration files for memory settings
- Add new test files for memory management

## Backward Compatibility
- Maintain existing API for gradual migration
- Add feature flags for new memory management
- Provide migration guide for configuration changes

## Priority
**Medium** - Important for production stability and scalability, but not immediately critical.

## Related Issues
- Array bounds violations can be prevented with better buffer management
- Sequence number fixes will improve memory allocation patterns
- Concurrency improvements needed for thread-safe memory management

## Acceptance Criteria
- [ ] Configurable memory limits with enforcement
- [ ] No memory leaks in long-running tests
- [ ] Dynamic page sizing based on traffic patterns
- [ ] Safe buffer operations with comprehensive bounds checking
- [ ] Memory usage monitoring and cleanup under pressure
- [ ] Performance equal to or better than current implementation
- [ ] Thread-safe memory management for concurrent access