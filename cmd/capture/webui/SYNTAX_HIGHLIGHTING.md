# Syntax Highlighting Implementation for Filter Expressions

## Overview

This document describes the comprehensive **inline** syntax highlighting implementation for filter expressions throughout the NETCAP webUI. All syntax highlighting now happens **directly within the input fields** - no separate preview boxes are shown.

## Components

### 1. Core Highlighting Libraries

#### Filter Expression Highlighting (expr-lang)

**File:** `src/lib/filterSyntaxHighlight.ts`

**Supported Syntax:**
- **Field names**: `DstPort`, `SrcIP`, `Timestamp`, etc. (light blue)
- **Operators**: `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, `!` (gray)
- **Functions**: `InSubnet()`, `IsPrivateIP()`, `contains()`, etc. (yellow)
- **String literals**: Single or double quoted strings (orange)
- **Numbers**: Integers and floats (light green)
- **Boolean literals**: `true`, `false` (blue)
- **Parentheses/Brackets**: Grouping operators (gold)

#### BPF Filter Highlighting

**File:** `src/lib/bpfSyntaxHighlight.ts`

**Supported Syntax:**
- **Protocols**: `tcp`, `udp`, `icmp`, `ip`, `arp`, etc. (blue)
- **Keywords**: `host`, `net`, `port`, `src`, `dst`, etc. (purple)
- **Operators**: `and`, `or`, `not`, `!`, `&&`, `||` (gray)
- **Numbers**: Port numbers, VLAN IDs (light green)
- **IP addresses**: IPv4/IPv6 addresses (teal)
- **MAC addresses**: Ethernet addresses (orange)

#### Regex Pattern Highlighting

**File:** `src/lib/regexSyntaxHighlight.ts`

**Supported Syntax:**
- **Flags**: `(?i)`, `(?m)`, etc. (purple)
- **Groups**: Capturing groups `(...)` (gold)
- **Character classes**: `[a-z]`, `[^0-9]` (teal)
- **Escape sequences**: `\w`, `\d`, `\s`, `\n`, `\t`, etc. (light green)
- **Hex codes**: `\x00` (orange)
- **Octal codes**: `\000` (orange)
- **Quantifiers**: `*`, `+`, `?`, `{n,m}`, `|` (red)
- **Backreferences**: `$1`, `$2` (yellow)
- **Anchors**: `^`, `$` (blue)

### 2. Inline Syntax Highlighting Components

#### SyntaxHighlightedInput / SyntaxHighlightedTextArea

**File:** `src/components/SyntaxHighlightedInput.tsx`

A text input/textarea component with real-time inline syntax highlighting. The component uses an overlay technique where:
1. The actual input text is rendered transparent
2. A syntax-highlighted overlay is positioned exactly over the input
3. The caret remains visible for editing

**Props:**
- `syntaxType`: `'filter' | 'bpf' | 'regex'` - Type of syntax to highlight
- `value`: string - The input value
- `onChange`: (value: string) => void - Change handler
- `enableHighlighting`: boolean (default: true) - Toggle highlighting
- `label`: string - Input label
- `helperText`: string - Helper text below input
- `multiline`: boolean - Whether to use textarea
- `rows`: number - Number of rows (for multiline)

**Usage Example:**
```tsx
import { SyntaxHighlightedTextArea } from '@/components/SyntaxHighlightedInput';

<SyntaxHighlightedTextArea
  syntaxType="bpf"
  value={bpfFilter}
  onChange={setBpfFilter}
  label="BPF Filter"
  placeholder="tcp port 80 or udp port 53"
  rows={4}
  fullWidth
/>
```

#### SyntaxHighlightedAutocomplete

**File:** `src/components/SyntaxHighlightedAutocomplete.tsx`

An autocomplete component with inline syntax highlighting for filter expressions. Preserves all Material-UI Autocomplete functionality while adding syntax highlighting overlay.

**Props:**
- All standard Autocomplete props
- Automatically highlights filter expressions in real-time

**Usage Example:**
```tsx
import SyntaxHighlightedAutocomplete from '@/components/SyntaxHighlightedAutocomplete';

<SyntaxHighlightedAutocomplete
  value={filterExpression}
  onChange={setFilterExpression}
  options={suggestions}
  label="Filter Expression"
  placeholder="e.g., DstPort == 443"
/>
```

### 3. Display-Only Components (for showing expressions, not editing)

These components are used to display syntax-highlighted expressions in tables, alerts, and other read-only contexts.

#### FilterExpressionHighlight / FilterExpressionBlock

**File:** `src/components/FilterExpressionHighlight.tsx`

- `FilterExpressionHighlight` - Inline display component
- `FilterExpressionInline` - Inline with ellipsis for tables
- `FilterExpressionBlock` - Block display with background

#### BPFExpressionHighlight / BPFExpressionBlock

**File:** `src/components/BPFExpressionHighlight.tsx`

- `BPFExpressionHighlight` - Inline display component
- `BPFExpressionBlock` - Block display with background

#### RegexHighlight / RegexBlock

**File:** `src/components/RegexHighlight.tsx`

- `RegexHighlight` - Inline display component
- `RegexBlock` - Block display with background

## Integration Points

### Pages with Inline Syntax Highlighting

1. **bpf.tsx** - BPF Filter Configuration Page
   - ✅ Inline syntax highlighting in filter input (4 rows, multiline)
   - No separate preview box

2. **rules.tsx** - Detection Rules Page
   - ✅ Inline syntax highlighting in expression editor (4 rows, multiline)
   - Display-only highlighting in rule table (inline)
   - No separate preview box

3. **probes.tsx** - Service Probes Page
   - ✅ Inline syntax highlighting for regex patterns (3 rows, multiline)
   - No separate preview box

4. **audit.tsx** - Audit Records Page
   - ✅ Inline syntax highlighting in filter input with autocomplete
   - No separate preview boxes
   - Full autocomplete functionality preserved (TAB, CTRL+SPACE)

5. **alerts.tsx** - Alerts Page
   - Display-only: Rule expressions shown in alert details

6. **analyze.tsx** - Analysis Page  
   - Display-only: Active BPF filter display

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

### Regex Colors:
- Flags: `#c586c0` (purple)
- Groups: `#ffd700` (gold)
- Character classes: `#4ec9b0` (teal)
- Escape sequences: `#b5cea8` (light green)
- Hex/Octal codes: `#ce9178` (orange)
- Quantifiers: `#f44336` (red)
- Backreferences: `#dcdcaa` (yellow)
- Anchors: `#569cd6` (blue)
- Plain text: `#d4d4d4` (light gray)

## Features

1. **Real-time Inline Highlighting**: As users type, syntax is highlighted directly in the input field
2. **No Preview Boxes**: All highlighting happens inline - cleaner UI
3. **Consistent Styling**: Unified color scheme across all pages
4. **Full Functionality**: All input features preserved (autocomplete, copy/paste, selection, etc.)
5. **Responsive Design**: Works in single-line and multi-line inputs
6. **Dark Mode Compatible**: Colors work well in dark theme
7. **Accessible**: Maintains proper focus, caret visibility, and text selection

## Technical Implementation

### Overlay Technique

The inline highlighting uses a layered approach:

1. **Highlight Overlay Layer**: Positioned absolutely over the input, contains colored syntax tokens, pointer-events disabled
2. **Input Layer**: Standard input/textarea with transparent text color, fully interactive
3. **Caret**: Remains visible using `caretColor` CSS property

This approach ensures:
- Real-time highlighting as you type
- All native input behaviors work (selection, copy/paste, autocomplete)
- No performance issues with large inputs
- Clean separation of concerns

### Example Structure:
```tsx
<Box sx={{ position: 'relative' }}>
  {/* Syntax-highlighted overlay */}
  <Box sx={{ position: 'absolute', pointerEvents: 'none', color: 'transparent' }}>
    {tokens.map(token => <span style={{ color: token.color }}>{token.value}</span>)}
  </Box>
  
  {/* Actual input (transparent text) */}
  <OutlinedInput
    sx={{ '& input': { color: 'transparent', caretColor: 'text.primary' } }}
  />
</Box>
```

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

To test the inline highlighting:

1. Navigate to BPF page (`/bpf`)
   - Type a BPF filter - verify inline syntax highlighting
   - No preview box should appear
   
2. Navigate to Rules page (`/rules`)
   - Create/edit a rule - verify expression highlighting inline
   - No preview box should appear
   
3. Navigate to Audit Records page (`/audit`)
   - Type a filter expression - verify inline highlighting
   - Test autocomplete with TAB - highlighting should update
   - No preview boxes should appear
   
4. Navigate to Service Probes page (`/probes`)
   - Edit a probe pattern - verify regex highlighting inline
   - No preview box should appear

## Future Enhancements

Potential improvements:
- Error highlighting for invalid syntax
- Syntax validation with inline error messages  
- Autocomplete with syntax-aware suggestions for BPF
- Custom themes for different user preferences
- Performance optimizations for very long expressions

