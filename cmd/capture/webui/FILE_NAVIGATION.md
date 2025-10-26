# File Navigation and Switching

This document describes the file navigation and switching features in the Web UI for multi-file processing mode.

## Overview

When processing multiple PCAP files, the Web UI provides seamless navigation between files and their associated audit records.

## Features

### 1. Automatic Navigation on File Selection

When you select an input file from the **Files** page, the UI automatically:
- Sets the file as the active viewing target
- Switches the backend to use that file's output directory
- **Navigates you directly to the Audit Records page**
- Refreshes all data to show that file's audit records

This eliminates the need to manually switch between pages after selecting a file.

### 2. File Selector on Audit Records Page

The **Audit Records** page now includes a file selector dropdown (when in multi-file mode):

```
┌─────────────────────────────────────────────────────────────┐
│ Network Protocol Analysis                    Viewing capture:│
│ 5 protocol type(s) found...                   [Switch] ▼    │
│                                              ┌───────────────┤
│                                              │ ✓ file1.pcap  │
│                                              │   file2.pcap  │
│                                              │   file3.pcap  │
│                                              └───────────────┘
└─────────────────────────────────────────────────────────────┘
```

**Location**: Top-right corner of the Audit Records page  
**Visibility**: Only shown when:
- Multi-file processing mode is active
- At least one file has completed processing

**Features**:
- Shows all **completed** files (processing files are excluded)
- Displays filename, size, and "Active" badge for current file
- Switch icon (⇄) indicator
- Loading spinner while switching
- Automatic refresh of audit records after switching

## User Workflows

### Workflow 1: Files Page → Auto-Navigate to Audit Records

1. Go to **Files** page
2. Click on any **completed** file (row or eye icon)
3. **Automatically navigate to Audit Records page**
4. View that file's audit records immediately

```
Files Page [Click File] → [Auto-switch] → Audit Records Page [Showing selected file]
```

### Workflow 2: Switch Files from Audit Records Page

1. While on **Audit Records** page
2. Click the **file selector dropdown** (top-right)
3. Select a different file
4. Audit records refresh automatically to show the new file's data

```
Audit Records [Click Dropdown] → [Select File] → [Auto-refresh] → New file's records shown
```

### Workflow 3: Browse Multiple Files

1. Start on **Files** page with many processed captures
2. Click first file → auto-navigate to Audit Records
3. Explore that file's protocols
4. Use **dropdown** to switch to next file (stay on Audit Records page)
5. Explore second file's protocols
6. Continue switching via dropdown as needed

**No need to return to Files page between files!**

## Visual Indicators

### Files Page

- ✅ **Green checkmark**: Active file (currently being viewed)
- ⏳ **Hourglass**: File still processing
- **Highlighted row**: Active file (light background)
- **Dimmed row**: Processing file (reduced opacity)
- **Eye icon button**: Quick action to switch and navigate

### Audit Records Page

- **Dropdown**: Shows current active file
- **"Active" badge**: Indicates current file in dropdown menu
- **Loading spinner**: Shows when switching files
- **File metadata**: Filename and size displayed in dropdown items

## Technical Details

### State Synchronization

Both pages listen for the `directory-changed` custom event, ensuring:
- All components stay synchronized
- Backend `outDir` is updated correctly
- SWR caches are invalidated and refreshed
- Global state is consistent across pages

### API Endpoint

```
POST /api/set-directory
Body: { "inputFile": "/path/to/file.pcap" }
Response: { "success": true, "outputDir": "/new/dir", "activeInputFile": "/path/to/file.pcap" }
```

### Router Navigation

Files page uses Next.js router to programmatically navigate:
```typescript
import { useRouter } from 'next/router';
const router = useRouter();
router.push('/audit'); // Navigate after file selection
```

## Benefits

1. **Faster Workflow**: Auto-navigation eliminates manual page switching
2. **Convenience**: Switch files without leaving Audit Records page
3. **Context Preservation**: Stay focused on audit records while exploring multiple files
4. **Visual Feedback**: Clear indicators show which file is active
5. **Seamless UX**: All transitions are smooth with loading states

## Example Usage

```bash
# Process multiple files
./bin/net capture \
  -read capture1.pcap \
  -read capture2.pcap \
  -read capture3.pcap \
  -out /tmp/multi-file \
  -http localhost:8080
```

Then:
1. Open browser to `http://localhost:8080/files`
2. Click on `capture1.pcap` → **Instantly view its protocols**
3. Use dropdown to switch to `capture2.pcap` → **Protocols refresh**
4. Use dropdown to switch to `capture3.pcap` → **Protocols refresh**
5. All without leaving the Audit Records page!

## Notes

- Only **completed** files appear in the dropdown (processing files are excluded)
- File switching triggers a full refresh of audit records
- The Files page remains useful for:
  - Viewing all files at once (with pagination)
  - Seeing completion status
  - Checking file metadata (size, modified time)
- The Audit Records dropdown is optimized for quick switching during analysis

