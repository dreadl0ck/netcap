# Quick Start Guide

## Build

```bash
cd /Users/pmieden/go/src/github.com/dreadl0ck/netcap
go build -o bin/net ./cmd
```

## Test (Without PCAP)

Just to see the UI:

```bash
mkdir -p /tmp/test-netcap
./bin/net capture -read "" -out /tmp/test-netcap -http localhost:8080
```

Then open: http://localhost:8080

You should see:
- ✅ Dashboard loads (no infinite spinner)
- ✅ Shows "0" for all statistics
- ✅ No JavaScript errors in console
- ✅ Can navigate between pages

## Test (With PCAP)

Process a real PCAP file:

```bash
./bin/net capture -read /path/to/traffic.pcap -out /tmp/netcap-output -http localhost:8080
```

Then open: http://localhost:8080

You should see:
- ✅ Dashboard shows processing status
- ✅ After completion, server keeps running
- ✅ Statistics update with real numbers
- ✅ Input Files page lists your PCAP
- ✅ Audit Records page lists generated types
- ✅ Can stream and view audit records
- ✅ Logs page shows log files
- ✅ Ctrl+C stops the server

## Troubleshooting

### Still seeing spinner?
- Hard refresh: `Ctrl+Shift+R` or `Cmd+Shift+R`
- Check console for errors (F12)
- Verify server is running (check terminal)

### Redirect loop?
- Clear browser cache
- Try different browser
- Check terminal logs for errors

### 404 errors?
- Verify build completed: `ls bin/net`
- Check frontend was built: `ls cmd/capture/webui/frontend/out/`
- Rebuild if needed: `go build -o bin/net ./cmd`

