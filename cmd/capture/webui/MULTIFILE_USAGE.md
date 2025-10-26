# Multi-File Processing Mode

When processing multiple PCAP files, Netcap creates a separate subdirectory for each file's audit records. The Web UI supports browsing these files individually.

## How It Works

### Backend Behavior

When you process multiple files:
```bash
./bin/net capture -read file1.pcap -read file2.pcap -read file3.pcap -out /tmp/output -http localhost:8080
```

Netcap creates this directory structure:
```
/tmp/output/
├── file1.pcap/
│   ├── TCP.ncap.gz
│   ├── UDP.ncap.gz
│   ├── HTTP.ncap.gz
│   └── ...
├── file2.pcap/
│   ├── TCP.ncap.gz
│   └── ...
└── file3.pcap/
    └── ...
```

### Web UI Features

1. **Multi-File Indicator**: The Files page shows a badge "Multi-file mode" when multiple files are being processed

2. **Clickable Files**: Each input file row is clickable

3. **Active File Indicator**: The currently selected file is:
   - Highlighted with a different background color
   - Marked with a green checkmark icon
   - Has a "Currently viewing" tooltip on the action button

4. **Switch Between Files**: Click any file to view its audit records:
   - Click the row itself
   - OR click the eye icon button in the Actions column

5. **Live Updates**: When you click a file:
   - The server switches to that file's output directory
   - The Audit Records page automatically shows records from that file
   - The Logs page shows logs from that file
   - The Dashboard updates to reflect the selected file

## API Endpoint

The Web UI uses the `/api/set-directory` endpoint to switch between files:

**Request:**
```json
POST /api/set-directory
{
  "inputFile": "/path/to/file.pcap"
}
```

**Response:**
```json
{
  "success": true,
  "outputDir": "/tmp/output/file.pcap",
  "activeInputFile": "/path/to/file.pcap"
}
```

## Status API Enhancement

The `/api/status` endpoint now includes:
```json
{
  "isProcessing": false,
  "outputDir": "/tmp/output/file1.pcap",
  "inputFiles": ["/path/to/file1.pcap", "/path/to/file2.pcap"],
  "activeInputFile": "/path/to/file1.pcap",
  "isMultiFile": true
}
```

- `activeInputFile`: The currently selected file for viewing
- `isMultiFile`: Boolean indicating if multiple files are being processed

## Usage Example

1. **Start capture with multiple files:**
   ```bash
   ./bin/net capture \
     -read capture1.pcap \
     -read capture2.pcap \
     -read capture3.pcap \
     -out /tmp/analysis \
     -http localhost:8080
   ```

2. **Open Web UI:**
   Navigate to http://localhost:8080

3. **View Files page:**
   - See all three input files listed
   - Notice "Multi-file mode" badge
   - First file may be automatically selected

4. **Switch between files:**
   - Click on `capture2.pcap` row
   - Or click the eye icon next to it
   - Selected file gets highlighted and checkmarked

5. **View audit records:**
   - Go to Audit Records page
   - You'll see records from the currently selected file
   - Click "View Records" on any type to stream them

6. **Switch to another file:**
   - Return to Files page
   - Click on `capture3.pcap`
   - Go back to Audit Records page
   - Now showing records from `capture3.pcap`

## Notes

- Single-file mode: If only one file is processed, multi-file features are hidden
- Processing state: You can switch files even while capture is still processing
- Directory naming: Subdirectories are named after the base filename of each PCAP

