# Syntax Highlighting Implementation for Filter Expressions

## Overview

This document describes the comprehensive syntax highlighting implementation for filter expressions throughout the NETCAP webUI.

## Components

### 1. Filter Expression Highlighting (expr-lang)

**Files:**
- `src/lib/filterSyntaxHighlight.ts` - Core tokenization and highlighting logic
- `src/components/FilterExpressionHighlight.tsx` - React components for display

**Supported Syntax:**
- **Field names**: `DstPort`, `SrcIP`, `Timestamp`, etc. (light blue)
- **Operators**: `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, `!` (gray)
- **Functions**: `InSubnet()`, `IsPrivateIP()`, `contains()`, etc. (yellow)
- **String literals**: Single or double quoted strings (orange)
- **Numbers**: Integers and floats (light green)
- **Boolean literals**: `true`, `false` (blue)
- **Parentheses/Brackets**: Grouping operators (gold)

**Components Provided:**
- `FilterExpressionHighlight` - Main component with customizable props
- `FilterExpressionInline` - Inline variant with ellipsis for table cells
- `FilterExpressionBlock` - Block variant for code displays

**Usage Example:**
```tsx
import { FilterExpressionBlock, FilterExpressionInline } from '@/components/FilterExpressionHighlight';

// Inline in table
<FilterExpressionInline expression="DstPort == 443 && IsPrivateIP(SrcIP)" maxWidth={300} />

// Block display
<FilterExpressionBlock expression="SrcPort == 80 || DstPort == 443" />
```

### 2. BPF Filter Highlighting

**Files:**
- `src/lib/bpfSyntaxHighlight.ts` - Core tokenization for BPF syntax
- `src/components/BPFExpressionHighlight.tsx` - React components for BPF display

**Supported Syntax:**
- **Protocols**: `tcp`, `udp`, `icmp`, `ip`, `arp`, etc. (blue)
- **Keywords**: `host`, `net`, `port`, `src`, `dst`, etc. (purple)
- **Operators**: `and`, `or`, `not`, `!`, `&&`, `||` (gray)
- **Numbers**: Port numbers, VLAN IDs (light green)
- **IP addresses**: IPv4/IPv6 addresses (teal)
- **MAC addresses**: Ethernet addresses (orange)

**Components Provided:**
- `BPFExpressionHighlight` - Main component
- `BPFExpressionBlock` - Block variant for BPF displays

**Usage Example:**
```tsx
import { BPFExpressionBlock } from '@/components/BPFExpressionHighlight';

<BPFExpressionBlock expression="tcp port 80 or udp port 53" />
```

## Integration Points

### Pages with Syntax Highlighting

1. **audit.tsx** - Audit Records Page
   - Filter input preview (expr-lang)
   - Active filter display
   - Filter examples with highlighting

2. **rules.tsx** - Detection Rules Page
   - Rule expression in table (inline)
   - Rule editor dialog with preview (block)

3. **bpf.tsx** - BPF Filter Configuration Page
   - Filter input preview
   - BPF examples with highlighting

4. **analyze.tsx** - Analysis Page
   - Active BPF filter display

5. **alerts.tsx** - Alerts Page
   - Rule expression in alert details

## Color Scheme

The highlighting uses VS Code Dark+ inspired colors for consistency:

### Expr-lang Colors:
- Fields: `#9cdcfe` (light blue)
- Operators: `#d4d4d4` (light gray)
- Functions: `#dcdcaa` (yellow)
- Strings: `#ce9178` (orange)
- Numbers: `#b5cea8` (light green)
- Booleans: `#569cd6` (blue)
- Parentheses: `#ffd700` (gold)

### BPF Colors:
- Protocols: `#569cd6` (blue)
- Keywords: `#c586c0` (purple)
- Operators: `#d4d4d4` (gray)
- Numbers: `#b5cea8` (light green)
- IPs: `#4ec9b0` (teal)
- Strings: `#ce9178` (orange)

## Features

1. **Real-time Preview**: As users type filter expressions, they see highlighted previews
2. **Example Highlighting**: All filter examples throughout the UI are highlighted
3. **Consistent Styling**: Unified color scheme across all pages
4. **Responsive Design**: Works in tables, dialogs, and full-width displays
5. **Tooltip Support**: Inline expressions show full text on hover
6. **Dark Mode Compatible**: Colors work well in dark theme

## Extending the Highlighting

### Adding New Field Names

Edit `src/lib/filterSyntaxHighlight.ts`:
```typescript
const COMMON_FIELDS = new Set([
  // ... existing fields
  'YourNewField',
]);
```

### Adding New Helper Functions

Edit `src/lib/filterSyntaxHighlight.ts`:
```typescript
const HELPER_FUNCTIONS = new Set([
  // ... existing functions
  'YourNewFunction',
]);
```

### Adding New BPF Keywords

Edit `src/lib/bpfSyntaxHighlight.ts`:
```typescript
const KEYWORDS = new Set([
  // ... existing keywords
  'yournewkeyword',
]);
```

## Testing

To test the highlighting:

1. Navigate to the Audit Records page (`/audit`)
2. Type a filter expression in the input field
3. Verify the preview shows colored syntax
4. Check the help examples are highlighted
5. Apply the filter and verify the active filter display
6. Navigate to Rules page (`/rules`)
7. Create/edit a rule and verify expression highlighting
8. Navigate to BPF page (`/bpf`)
9. Enter a BPF filter and verify BPF syntax highlighting

## Future Enhancements

Potential improvements:
- Error highlighting for invalid syntax
- Autocomplete with syntax-aware suggestions
- Syntax validation with inline error messages
- Custom themes for different user preferences
- Export highlighted expressions as images
- Search/replace with syntax preservation

