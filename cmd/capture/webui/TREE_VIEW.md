# Tree-Based Hierarchical Audit Records View

The Audit Records page now displays protocols in a beautiful tree structure that visually represents the network stack hierarchy, inspired by `net util -decoders`.

## Overview

Instead of a flat table, the UI now shows:
- **Collapsible layers** representing the OSI/TCP-IP stack
- **Tree visualization** with connectors showing parent-child relationships
- **Color-coded layers** for quick visual identification
- **Only protocols found in the capture** (no empty categories)
- **Grouped statistics** showing count per layer

## Visual Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ Network Protocol Analysis        📁 Source: capture.pcap        │
│ 12 protocol type(s) found • Hierarchical by encapsulation layer │
└─────────────────────────────────────────────────────────────────┘

🔵 ▼ Link Layer                                              2 types
    ├─ 📄 Ethernet                    1,234 records    2.1MB  [View]
    └─ 📄 ARP                             45 records     12KB  [View]

🟢 ▼ Network Layer                                           3 types
    ├─ 📄 IPv4                        5,678 records    8.3MB  [View]
    ├─ 📄 IPv6                          234 records    456KB  [View]
    └─ 📄 ICMPv4                         89 records     56KB  [View]

🟠 ▼ Transport Layer                                         2 types
    ├─ 📄 TCP                         9,012 records     15MB  [View]
    └─ 📄 UDP                         1,567 records    2.3MB  [View]

🟣 ▼ Application Layer                                       3 types
    ├─ 📄 DNS                           234 records    123KB  [View]
    ├─ 📄 TLSClientHello                 56 records     67KB  [View]
    └─ 📄 Connection                    123 records     89KB  [View]

🔴 ▼ Abstract Decoders                                       2 types
    ├─ 📄 Software                       12 records      8KB  [View]
    └─ 📄 Service                        34 records     23KB  [View]
```

## Features

### 1. Hierarchical Grouping

Protocols are automatically grouped by their encapsulation layer:
- **Link Layer** (Blue) - Physical/data link protocols
- **Network Layer** (Green) - IP, ICMP, routing
- **Transport Layer** (Orange) - TCP, UDP, SCTP
- **Application Layer** (Purple) - DNS, HTTP, TLS, etc.
- **Stream Decoders** (Cyan) - Reassembled streams
- **Abstract Decoders** (Red) - Derived analysis data

### 2. Expand/Collapse Layers

- Click any layer header to expand or collapse it
- Chevron icon indicates state (▼ expanded, ► collapsed)
- Initial state: Common layers expanded by default
- State persists while navigating

### 3. Visual Tree Connectors

Each protocol entry shows:
- Horizontal connector (─) linking to parent layer
- File icon (📄) indicating it's a leaf node
- Clear visual hierarchy through indentation

### 4. Color-Coded Layers

Each layer has a unique color stripe:
- **Blue** (#2196F3) - Link Layer
- **Green** (#4CAF50) - Network Layer
- **Orange** (#FF9800) - Transport Layer
- **Purple** (#9C27B0) - Application Layer
- **Cyan** (#00BCD4) - Stream Decoders
- **Red** (#F44336) - Abstract Decoders

### 5. Compact Information Display

For each protocol:
- **Protocol name** in monospace font (bold)
- **Filename** below in smaller monospace
- **Record count** with "records" label
- **File size** with size label
- **"View Records"** button to stream data

### 6. Dynamic Content

- **Only shows layers that have data** (empty layers hidden)
- **Type count per layer** shown in chip badge
- **Total protocols found** in header
- **Source file indicator** in multi-file mode

## Benefits

### Better Understanding of Network Stack

The tree view helps users understand:
- Which protocols were captured at each layer
- The hierarchical relationship between protocols
- Where data flows through the network stack
- What analysis was performed (Abstract Decoders)

### Cleaner Interface

- Less visual clutter than table view
- Easier to scan for specific protocols
- Natural grouping reduces cognitive load
- Collapsible sections save screen space

### Protocol Discovery

- Quickly see what was captured
- Identify missing protocols
- Understand capture completeness
- Find abstract analysis results

## Comparison: Before vs After

### Before (Table View)
```
┌────────────┬──────────┬──────────────┬──────────┬───────┬─────────┐
│ Layer      │ Type     │ Filename     │ Records  │ Size  │ Actions │
├────────────┼──────────┼──────────────┼──────────┼───────┼─────────┤
│ Link...    │ Ethernet │ Ethernet...  │ 1,234    │ 2.1MB │ [View]  │
│ Link...    │ ARP      │ ARP.ncap.gz  │ 45       │ 12KB  │ [View]  │
│ Network... │ IPv4     │ IPv4.ncap.gz │ 5,678    │ 8.3MB │ [View]  │
│ Network... │ ICMPv4   │ ICMPv4...    │ 89       │ 56KB  │ [View]  │
...
```

**Issues:**
- Repetitive layer column
- No visual hierarchy
- Hard to see grouping
- Takes more vertical space
- Layer colors not prominent

### After (Tree View)
```
🔵 ▼ Link Layer (2 types)
    ├─ Ethernet    1,234 records  2.1MB  [View]
    └─ ARP            45 records    12KB  [View]

🟢 ▼ Network Layer (2 types)
    ├─ IPv4        5,678 records  8.3MB  [View]
    └─ ICMPv4         89 records    56KB  [View]
```

**Benefits:**
- Clear visual hierarchy
- Collapsible sections
- Color-coded layers
- Less repetition
- Easier to scan

## Implementation Details

### Frontend Structure

```typescript
interface LayerGroup {
  layerName: string;
  files: any[];
}

// Group files by layer
const layerGroups = useMemo(() => {
  const groups = new Map<string, any[]>();
  files.forEach(file => {
    const layer = file.layer || 'Other';
    if (!groups.has(layer)) {
      groups.set(layer, []);
    }
    groups.get(layer)!.push(file);
  });
  
  // Return in hierarchical order
  return layerOrder
    .filter(name => groups.has(name))
    .map(name => ({ layerName: name, files: groups.get(name)! }));
}, [files]);
```

### Expand/Collapse State

```typescript
const [expandedLayers, setExpandedLayers] = useState<Set<string>>(
  new Set(['Link Layer', 'Network Layer', 'Transport Layer', 'Application Layer'])
);

const toggleLayer = (layerName: string) => {
  setExpandedLayers(prev => {
    const newSet = new Set(prev);
    if (newSet.has(layerName)) {
      newSet.delete(layerName);
    } else {
      newSet.add(layerName);
    }
    return newSet;
  });
};
```

### Color Mapping

```typescript
function getLayerColor(layerName: string): string {
  const colorMap: Record<string, string> = {
    'Link Layer': '#2196F3',
    'Network Layer': '#4CAF50',
    'Transport Layer': '#FF9800',
    'Application Layer': '#9C27B0',
    'Stream Decoders': '#00BCD4',
    'Abstract Decoders': '#F44336',
    'Other': '#9E9E9E',
  };
  return colorMap[layerName] || '#9E9E9E';
}
```

## User Interaction

### Expanding a Layer
1. Click layer header
2. Chevron rotates from ► to ▼
3. Protocol list smoothly expands with animation
4. All protocol details become visible

### Viewing Records
1. Click "View Records" button on any protocol
2. Dialog opens showing streaming records
3. Progress indicator during load
4. JSON records displayed in readable format

### Multi-File Mode
1. Select different input file on Files page
2. Event triggers refresh of audit records
3. Tree view updates to show that file's protocols
4. Source chip badge updates with filename

## Accessibility

- **Keyboard navigation** supported on all interactive elements
- **Screen reader friendly** with proper ARIA labels
- **High contrast** colors for visual distinction
- **Clear visual hierarchy** through indentation
- **Tooltips** on hover for additional context

## Performance

- **Memoized grouping** prevents unnecessary recalculation
- **Lazy rendering** only shows expanded content
- **Efficient state management** with React hooks
- **Smooth animations** using Material-UI Collapse
- **Responsive design** adapts to screen size

## Matching `net util -decoders`

The tree structure closely matches the output of:
```bash
./bin/net util -decoders
```

Both show:
- Hierarchical indentation
- Layer grouping
- Clear parent-child relationships
- Protocol type names
- Organized by encapsulation level

The Web UI adds:
- Interactive expand/collapse
- Real-time statistics
- Visual styling and colors
- Action buttons for viewing data
- Only shows what's actually captured

## Future Enhancements

Potential additions:
- Search/filter within tree
- Expand/collapse all button
- Drill-down into protocol relationships
- Packet flow visualization
- Timeline view integration
- Export tree structure

## Testing

```bash
cd /Users/pmieden/go/src/github.com/dreadl0ck/netcap

./bin/net capture -read traffic.pcap -out /tmp/tree-test -http localhost:8080
```

Navigate to Audit Records page and verify:
- ✅ Tree structure displays
- ✅ Layers are collapsible
- ✅ Only captured protocols shown
- ✅ Colors match layers
- ✅ Statistics are accurate
- ✅ View Records button works
- ✅ Smooth expand/collapse animations
- ✅ Responsive on different screen sizes

The new tree view provides an intuitive, visually appealing way to explore captured network protocols!

