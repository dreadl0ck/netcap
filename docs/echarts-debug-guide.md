# ECharts 3D Debug Guide

## Summary

Fixed 3D charts not loading by:
1. Adding required ECharts v4 files for 3D support
2. Properly embedding all assets in the Go binary
3. Setting correct Content-Type headers
4. Adding comprehensive debug logging

## Files Embedded

All required files are now embedded (verified by test):

```
✓ static/echarts/echarts.min.js (1,024,695 bytes) - ECharts v6
✓ static/echarts/echarts@4.min.js (785,467 bytes) - ECharts v4 (required for 3D)
✓ static/echarts/echarts-gl.min.js (687,678 bytes) - 3D extension
✓ static/echarts/themes/macarons.js (5,869 bytes) - Theme file
```

## Verification

Run the embedded assets test:
```bash
cd cmd/capture/webui
go test -v -run TestEmbedded
```

Expected output: All files found ✓

## Debug Logs to Look For

### 1. Server Startup Logs

When the server starts, you should see:

```
========================================
Web UI server starting on http://0.0.0.0:80
Service mode: true
Assets path: 
Using EMBEDDED assets (not filesystem)
========================================
```

### 2. Asset Handler Initialization

```
========================================
[WebUI] *** SERVING EMBEDDED ASSETS ***
[WebUI] Root: frontend/out
========================================
[WebUI] Embedded echarts files found:
[WebUI]   ✓ static/echarts/echarts-gl.min.js
[WebUI]   ✓ static/echarts/echarts-wordcloud.min.js
[WebUI]   ✓ static/echarts/echarts.min.js
[WebUI]   ✓ static/echarts/echarts@4.min.js
[WebUI]   ✓ static/echarts/maps/world.js
[WebUI]   ✓ static/echarts/themes/macarons.js
[WebUI]   ✓ static/echarts/world.js
[WebUI] Total echarts files embedded: 7
========================================
```

### 3. Request Logs

When browser requests echarts files:

```
[WebUI] >>> ECHARTS REQUEST: /static/echarts/echarts@4.min.js (method=GET, from=192.168.1.100:52431)
[WebUI] *** ECHARTS JS: /static/echarts/echarts@4.min.js | Status=200 | OldType="text/plain; charset=utf-8" | NewType=application/javascript
```

### 4. Error Logs (if files not found)

```
[WebUI] !!!!! 404 ECHARTS FILE NOT FOUND: /static/echarts/echarts@4.min.js
```

## Troubleshooting

### No Logs Appearing?

1. **Check log output location**:
   - Local mode: stdout
   - Service mode: Check systemd logs or docker logs
   - Example: `journalctl -u netcap -f` or `docker logs -f netcap`

2. **Verify server is using embedded assets**:
   - Look for "Using EMBEDDED assets" in startup logs
   - If you see "Serving assets from filesystem", the `-http-assets` flag is set

3. **Check if server is actually starting**:
   - Look for "Web UI server starting on" message
   - Check for port conflicts

### Files Still 404?

1. **Check embed worked**:
   ```bash
   cd cmd/capture/webui
   go test -v -run TestEmbeddedEchartsFiles
   ```

2. **Verify rebuild**:
   - Frontend: `zeus build-frontend`
   - Backend: `zeus install`
   - Both changes must be deployed

3. **Check URL paths**:
   - Correct: `/static/echarts/echarts@4.min.js`
   - Wrong: `/echarts@4.min.js`

### Content-Type Still Wrong?

The `responseWriterWrapper` forces correct Content-Type headers. If still seeing MIME errors:

1. Check browser cache (hard refresh: Ctrl+Shift+R)
2. Check if a proxy/CDN is caching old responses
3. Verify the wrapper is being called (check logs for "ECHARTS JS" messages)

## Testing Locally

1. Start server in local mode:
   ```bash
   net capture -read test.pcap -out /tmp/test -http localhost:8080
   ```

2. Watch logs for startup messages

3. Open browser to http://localhost:8080/visualize

4. Open browser console and network tab

5. Check for echarts requests and responses

## Deployment Checklist

- [ ] Frontend built with `zeus build-frontend`
- [ ] Backend built with `zeus install`  
- [ ] Binary deployed to production
- [ ] Server restarted
- [ ] Startup logs show "SERVING EMBEDDED ASSETS"
- [ ] Startup logs list all 7 echarts files
- [ ] Browser requests show 200 status codes
- [ ] Browser console shows no MIME type errors
- [ ] 3D charts render correctly

