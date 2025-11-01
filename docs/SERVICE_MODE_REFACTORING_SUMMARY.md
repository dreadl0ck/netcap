# Service Mode Refactoring Summary

**Date:** October 27, 2025  
**Version:** v0.7.7

## Overview

Successfully refactored the `try` subcommand into a service mode flag for the `capture` command. This consolidates the codebase and simplifies the architecture by making service mode an operational mode rather than a separate subcommand.

## Changes Made

### 1. Architecture Changes

**Before:**
- `net try` - Separate subcommand for service mode
- `cmd/try/` - Separate package with its own main
- `internal/webui/` - Shared webUI package

**After:**
- `net capture --service` - Service mode flag
- `cmd/capture/service/` - Service implementation as subpackage
- `cmd/capture/webui/` - Single webUI location used by both modes

### 2. New Command Structure

**Standard Capture Mode:**
```bash
net capture -read traffic.pcap -out results/
```

**Service Mode:**
```bash
net capture --service -http localhost:7070
```

### 3. Service Mode Flags

New flags added to the capture command:

- `--service` - Enable service mode for multi-file upload and analysis
- `--service-data-dir` - Directory for uploads and results (default: auto-detect)
- `--service-max-file-size` - Maximum upload file size (default: 100MB)
- `--service-max-per-hour` - Maximum analyses per IP per hour (default: 10)
- `--service-expiry` - Session expiry time in minutes (default: 60)
- `--service-cleanup` - Cleanup check interval in minutes (default: 10)
- `--service-max-storage` - Maximum total storage (default: 10GB, 0 = unlimited)

### 4. File Structure Changes

**Created:**
- `cmd/capture/service/` - Service mode implementation
  - `config.go` - Service configuration
  - `session.go` - Session management
  - `server.go` - HTTP server and lifecycle
  - `handlers.go` - API handlers
  - `static.go` - Frontend asset serving
  - `system_*.go` - System information handlers
- `cmd/capture/service_mode.go` - Entry point for service mode

**Modified:**
- `cmd/capture/flags.go` - Added service mode flags
- `cmd/capture/main.go` - Added service mode detection
- `cmd/capture/webui/` - Consolidated webUI implementation
  - Removed dependency on `internal/webui`
  - Added shared files (reader.go, sorting.go, types.go, utils.go, shared_handlers.go)
  - Exported `EmbeddedAssets` for use by service mode

**Removed:**
- `cmd/try/` - Entire try subcommand directory
- `internal/webui/` - Shared webUI package (consolidated into cmd/capture/webui)

### 5. Build System Updates

**zeus/commands.yml:**
- Renamed `build-try-server` to `build-service`
- Updated command to build container that runs `net capture --service`
- Updated `build-frontend` help text to reflect single location
- Simplified frontend build process

**Docker:**
- Renamed `docker/try/` directory to `docker/service/`
- Updated `docker/service/Dockerfile` to run `net capture --service` instead of `net try`
- Updated `docker/service/entrypoint.sh` with new service flag names
- Updated `docker/service/docker-compose.yml` with new service names
- Container image name changed from `netcap-try` to `netcap-service`

### 6. Benefits

1. **Simplified Architecture:** Service mode is now a runtime mode, not a separate binary
2. **Single WebUI:** Both standard and service modes use the same frontend
3. **Reduced Duplication:** Eliminated duplicate webUI code
4. **Easier Maintenance:** All capture-related code is in one location
5. **Consistent User Experience:** Same command, different modes
6. **Simplified Deployment:** One binary, multiple modes

### 7. Usage Examples

**Standard Capture with WebUI:**
```bash
net capture -read traffic.pcap -out results/ -http localhost:8080
```

**Service Mode:**
```bash
# Start service mode on port 7070
net capture --service -http localhost:7070

# With custom data directory
net capture --service -http localhost:7070 --service-data-dir /var/netcap/data

# With custom limits
net capture --service -http localhost:7070 \
  --service-max-file-size 104857600 \
  --service-max-per-hour 5 \
  --service-max-storage 21474836480
```

### 8. Migration Guide

For users previously using `net try`:

**Before:**
```bash
net try -http localhost:7070 -data-dir /data -dpi
```

**After:**
```bash
net capture --service -http localhost:7070 --service-data-dir /data -dpi
```

### 9. Testing

- ✅ Code compiles successfully
- ✅ Service mode flags visible in help output
- ✅ Try subcommand removed from main help
- ✅ WebUI consolidation complete
- ✅ Frontend embeds correctly from single location

### 10. Backward Compatibility

⚠️ **Breaking Change:** The `net try` subcommand no longer exists. Users must update scripts and documentation to use `net capture --service` instead.

### 11. Future Improvements

Potential enhancements for future releases:

1. Add service mode configuration file support
2. Implement rate limiting per user/API key
3. Add authentication/authorization layer
4. Implement result caching
5. Add metrics and monitoring endpoints
6. Support for distributed processing

## Conclusion

The refactoring successfully consolidates the service mode functionality into the capture command, simplifying the codebase while maintaining all functionality. The architecture is now cleaner, more maintainable, and easier to understand.

