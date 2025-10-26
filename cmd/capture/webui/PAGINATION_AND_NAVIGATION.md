# Pagination and Enhanced Navigation Features

This document summarizes the recent enhancements to the Web UI for improved file browsing and navigation.

## New Features Implemented

### 1. Input Files Pagination

**Location**: Files page (`/files`)

**Features**:
- Paginate through large lists of input files
- Configurable page sizes: 10, 25, 50, 100, or "All"
- Two UI controls:
  - **Top-right dropdown**: Quick page size selector (shows when >10 files)
  - **Bottom pagination bar**: Full controls with page navigation
- Smart visibility: Only shows pagination when needed
- Page state resets when changing page size

**UI Components**:
```
┌─────────────────────────────────────────────────────────────┐
│ Input PCAP Files                               Show: [10 ▼] │
│ 127 file(s) processed  [Multi-file mode]                    │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ [File table with 10 rows]                                   │
├─────────────────────────────────────────────────────────────┤
│ Files per page: [10 ▼]            1-10 of 127   [<] [>]    │
└─────────────────────────────────────────────────────────────┘
```

**Benefits**:
- Performance: Only renders visible files
- Usability: Easy navigation through hundreds of files
- Flexibility: Choose comfortable viewing size
- Clean UI: Hides when not needed (≤10 files)

### 2. Auto-Navigation on File Selection

**Location**: Files page → Audit Records page

**Behavior**: When you click on a file (row or eye icon):
1. Switches backend to that file's output directory
2. Updates global state
3. **Automatically navigates to Audit Records page**
4. Shows that file's protocols immediately

**Before**: 
```
Files Page → Click file → [Manual navigation needed] → Audit Records
```

**After**:
```
Files Page → Click file → [Auto-navigate] → Audit Records ✓
```

### 3. File Selector on Audit Records Page

**Location**: Audit Records page (`/audit`)

**Features**:
- Dropdown selector in top-right corner
- Only shows in multi-file mode
- Lists all **completed** files (excludes in-progress)
- Rich dropdown items showing:
  - "Active" badge for current file
  - Filename (monospace font)
  - File size
- Switch icon (⇄) indicator
- Loading spinner during switches
- Automatic audit records refresh after switching

**UI Component**:
```
┌─────────────────────────────────────────────────────────────┐
│ Network Protocol Analysis         Viewing capture:          │
│ 5 protocol type(s) found...       ┌──────────────────────┐ │
│                                    │ [⇄] capture1.pcap ▼ │ │
│                                    └──────────────────────┘ │
│                                    ┌──────────────────────┐ │
│                                    │ [Active] file1.pcap  │ │
│                                    │         file2.pcap   │ │
│                                    │         file3.pcap   │ │
│                                    └──────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Benefits**:
- No need to return to Files page between analyses
- Quick context switching during investigations
- Maintains workflow focus on protocol analysis
- Visual feedback shows current file

## Enhanced User Workflows

### Workflow A: Initial File Selection
1. **Files Page**: View all input files with pagination
2. **Click any completed file**: Instantly navigate to its audit records
3. **Start analysis**: Immediately see protocols and layers

### Workflow B: Multi-File Analysis
1. **Files Page**: Select first file (auto-navigate to Audit Records)
2. **Audit Records Page**: Analyze first file's protocols
3. **Use dropdown**: Switch to second file (stays on page)
4. **Continue**: Switch through multiple files without leaving page

### Workflow C: Large File Sets
1. **Files Page**: 127 files loaded
2. **Pagination**: Show 25 per page
3. **Navigate**: Use page controls to browse
4. **Select**: Click file from any page
5. **Analyze**: Automatically view its audit records
6. **Switch**: Use dropdown to jump to any other completed file

## Technical Implementation

### Files Page Changes

**Added**:
- `useRouter` hook for navigation
- `page` and `rowsPerPage` state
- Pagination slice logic
- Two dropdown change handlers
- `TablePagination` component
- Auto-navigation on file selection: `router.push('/audit')`

**Files Modified**:
- `/cmd/capture/webui/frontend/src/pages/files.tsx`

### Audit Records Page Changes

**Added**:
- `inputFiles` SWR data fetch
- File selector dropdown component
- `handleFileChange` function
- `switchingFile` loading state
- `completedFiles` filter
- `SwapHorizIcon` for visual indication

**Files Modified**:
- `/cmd/capture/webui/frontend/src/pages/audit.tsx`

### State Synchronization

Both pages coordinate via:
1. **API calls**: Update backend directory
2. **SWR mutations**: Refresh cached data
3. **Custom events**: `directory-changed` event broadcast
4. **Router navigation**: Programmatic page transitions

## Code Examples

### Pagination Implementation
```typescript
// State
const [page, setPage] = useState(0);
const [rowsPerPage, setRowsPerPage] = useState(10);

// Slice data
const paginatedFiles = sortedFiles.slice(
  page * rowsPerPage,
  page * rowsPerPage + rowsPerPage
);

// Render paginated
{paginatedFiles.map((file) => ...)}
```

### Auto-Navigation
```typescript
const router = useRouter();

const handleSelectFile = async (file: string) => {
  await api.setActiveDirectory(file);
  router.push('/audit'); // Navigate!
};
```

### File Selector
```typescript
<Select
  value={status?.activeInputFile}
  onChange={handleFileChange}
  startAdornment={<SwapHorizIcon />}
>
  {completedFiles.map((file) => (
    <MenuItem value={file.path}>
      {file.name} - {formatBytes(file.size)}
    </MenuItem>
  ))}
</Select>
```

## Performance Considerations

1. **Pagination**: Only renders visible files (10-100 vs potentially 1000+)
2. **Lazy loading**: Files loaded on-demand via SWR
3. **State caching**: SWR caches prevent unnecessary refetches
4. **Optimistic UI**: Loading states show during transitions
5. **Event-based updates**: Custom events only trigger necessary refreshes

## Testing Checklist

- [ ] Pagination shows when >10 files
- [ ] Pagination hides when ≤10 files
- [ ] Page size changes correctly
- [ ] Page navigation works (prev/next)
- [ ] "All" option shows all files
- [ ] Clicking file navigates to Audit Records
- [ ] Audit Records shows correct file's data
- [ ] File selector appears in multi-file mode
- [ ] File selector only shows completed files
- [ ] Switching files refreshes audit records
- [ ] "Active" badge shows on current file
- [ ] Loading spinner shows during switch
- [ ] All transitions are smooth

## Browser Compatibility

- ✅ Chrome/Edge (Chromium)
- ✅ Firefox
- ✅ Safari
- ✅ Responsive design (mobile/tablet)

## Future Enhancements

Potential improvements:
- Search/filter within paginated files
- Sort by different columns (size, date, status)
- Keyboard shortcuts for navigation
- Breadcrumb trail showing file selection path
- Bookmarkable URLs with active file parameter
- File comparison view (side-by-side)

## Summary

These enhancements significantly improve the user experience when working with multiple PCAP files:

1. **Pagination**: Handle large file sets efficiently
2. **Auto-navigation**: Reduce clicks and cognitive load  
3. **File selector**: Enable quick context switching during analysis

Combined, these features create a seamless, professional workflow for network traffic analysis across multiple capture files.

