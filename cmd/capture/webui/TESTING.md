# Web UI Testing Guide

## Quick Test

After rebuilding (`go build -o bin/net ./cmd`), test the Web UI:

### 1. Test with a PCAP file

```bash
./bin/net capture -read /path/to/traffic.pcap -out /tmp/test-output -http localhost:8080
```

Then open `http://localhost:8080` in your browser.

### 2. What to Check

#### Dashboard Page
- [ ] Page loads without infinite spinner
- [ ] Processing status shows "Complete" (green checkmark) after processing finishes
- [ ] Statistics cards show correct numbers:
  - Input Files count
  - Audit Record Types count
  - Total Records count
  - Log Files count
- [ ] Output directory path is displayed correctly
- [ ] Server start time is shown

#### Input Files Page
- [ ] Navigate to "Input Files" in sidebar
- [ ] Table shows all processed PCAP files
- [ ] File sizes are human-readable (e.g., "1.2 MB")
- [ ] Paths are complete and correct

#### Audit Records Page
- [ ] Navigate to "Audit Records" in sidebar
- [ ] Table lists all audit record types
- [ ] Record counts are shown
- [ ] Click "View Records" button
- [ ] Modal opens with streaming records
- [ ] Records appear as formatted JSON
- [ ] Progress updates show during loading
- [ ] Close button works

#### Logs Page
- [ ] Navigate to "Logs" in sidebar
- [ ] Table lists all log files
- [ ] Click "View Log" button
- [ ] Modal opens with log contents
- [ ] Log text is readable in monospace font
- [ ] Close button works

### 3. Check Browser Console

Open browser DevTools (F12) and check:
- No JavaScript errors in console
- Network tab shows successful API calls:
  - `GET /api/status` → 200 OK
  - `GET /api/files/input` → 200 OK
  - `GET /api/files/audit` → 200 OK
  - `GET /api/files/logs` → 200 OK

### 4. Check Terminal Output

In the terminal where you ran `net capture`, you should see:
```
[WebUI] GET /api/status
[WebUI] GET /api/files/input
[WebUI] GET /api/files/audit
[WebUI] GET /api/files/logs
```

These log messages confirm the API is receiving requests.

## Troubleshooting

### Infinite Loading Spinner

**Problem**: Dashboard shows spinning loader forever

**Solutions**:
1. **Check browser console** for errors:
   - Press F12 → Console tab
   - Look for red error messages
   - Common issues: CORS errors, network failures, JSON parse errors

2. **Check API responses**:
   - Press F12 → Network tab
   - Refresh page
   - Click on `/api/status` request
   - Check response status (should be 200)
   - Check response body (should be valid JSON)

3. **Verify server is running**:
   - Terminal should show "Web UI server starting on..."
   - Try accessing `http://localhost:8080/api/status` directly in browser
   - Should see JSON response

4. **Check for port conflicts**:
   - If port 8080 is in use, try a different port:
     ```bash
     ./bin/net capture -read file.pcap -out output -http localhost:8081
     ```

### Empty Data / "0 records"

**Problem**: UI loads but shows 0 for everything

**Possible causes**:
1. Processing hasn't started yet (wait a moment)
2. Output directory is empty (no audit records created)
3. Wrong output directory path

**Solutions**:
- Check the "Output directory" field on dashboard
- Verify that directory exists and has `.ncap.gz` files
- Try processing a larger PCAP file to generate more data

### API Returns 404

**Problem**: Browser shows 404 errors for `/api/*` requests

**Causes**:
- Server not running
- Wrong URL/port
- Firewall blocking

**Solutions**:
- Verify you're accessing the correct address (check terminal output)
- Try `http://127.0.0.1:8080` instead of `http://localhost:8080`
- Disable firewall temporarily for testing

### CORS Errors

**Problem**: Browser console shows "blocked by CORS policy"

**This shouldn't happen** because CORS is enabled for all origins.

If it does happen:
- You might be accessing from a different domain/port
- Try accessing from the same origin as the server
- Check server logs for CORS-related messages

## Testing Edge Cases

### No Input Files
```bash
./bin/net capture -read "" -out /tmp/empty -http localhost:8080
```
Expected: Empty arrays, no errors, "0" statistics

### Large PCAP Files (>100MB)
Test audit record streaming:
- Process a large PCAP
- Open Audit Records page
- Click "View Records" on a type with many records
- Verify streaming works smoothly
- Check memory usage doesn't spike

### Multiple Files
```bash
./bin/net capture -read "*.pcap" -out /tmp/multi -http localhost:8080
```
Expected: All files listed, combined statistics

## Performance Testing

### Load Time
- Dashboard should load in < 1 second
- API calls should complete in < 500ms
- Audit record streaming should start immediately

### Memory Usage
- Server should use < 100MB RAM when idle
- Streaming 1000 audit records should add < 50MB
- No memory leaks (memory should stabilize)

## Development Testing

### Frontend Dev Mode

1. Start frontend dev server:
```bash
cd cmd/capture/webui/frontend
npm run dev
```

2. Start capture with dev assets:
```bash
./bin/net capture -read file.pcap -out output \
  -http localhost:8080 \
  -http-assets http://localhost:3000
```

3. Access `http://localhost:8080` (proxies to dev server)
4. Make changes to frontend code
5. Changes should hot-reload in browser

## Automated Testing (Future)

Consider adding:
- [ ] Unit tests for API handlers
- [ ] Integration tests for SSE streaming
- [ ] E2E tests with Playwright/Cypress
- [ ] Performance benchmarks
- [ ] Load testing with multiple concurrent users

## Known Issues

1. **First request to large audit file may be slow**: Counting records takes time
2. **No real-time updates during processing**: Dashboard only updates every 2 seconds
3. **No authentication**: Don't expose on public networks
4. **No search/filtering**: Can't search within audit records yet

## Success Checklist

Before marking as complete, verify:
- [ ] Frontend builds without errors
- [ ] Go binary compiles successfully
- [ ] Dashboard loads without infinite spinner
- [ ] All four pages (Dashboard, Files, Audit, Logs) work
- [ ] API endpoints return valid JSON
- [ ] Audit record streaming works with SSE
- [ ] Log viewing works
- [ ] Keep-alive works (server stays running after processing)
- [ ] Ctrl+C cleanly shuts down server
- [ ] Browser console has no errors
- [ ] Server logs show incoming requests
- [ ] Documentation is up-to-date

