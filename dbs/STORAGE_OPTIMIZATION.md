# Database Server Storage Optimization

## Overview

The Netcap database server is designed to automatically manage storage by keeping only the most recent version of the databases. This prevents disk space exhaustion when running the server long-term.

## How It Works

### Automatic Cleanup Process

After each successful database rebuild, the server automatically:

1. **Identifies old versions** - Scans the `dbs` directory for dated files (YYYY-MM-DD pattern)
2. **Preserves current version** - Keeps the newly generated tarball and metadata
3. **Preserves symlinks** - Keeps the `latest.tar.gz` and `latest.json` symlinks
4. **Removes old files** - Deletes all previous version tarballs and metadata
5. **Reports cleanup** - Logs the number of files removed and space freed

### What Gets Deleted

The cleanup process removes:
- Old database tarballs (e.g., `2024-01-14.tar.gz`)
- Old metadata files (e.g., `2024-01-14.json`)

### What Gets Preserved

The cleanup process preserves:
- Current version tarball (e.g., `2024-01-15.tar.gz`)
- Current version metadata (e.g., `2024-01-15.json`)
- Latest symlinks (`latest.tar.gz` and `latest.json`)
- Build directory and temporary artifacts (cleaned on next rebuild)

## Storage Requirements

With automatic cleanup enabled:

**During Rebuild:**
- ~10-15 GB total (old version + build artifacts + new version)

**After Cleanup:**
- ~5-10 GB total (current version only)

**Long-term:**
- Storage usage remains constant at ~5-10 GB
- No growth over time regardless of how many rebuilds occur

## Implementation Details

### Code Location

The cleanup logic is implemented in `dbs/server.go`:
- Function: `cleanupOldVersions()`
- Called by: `rebuildDatabases()` after successful generation
- Thread-safe: Uses mutex to prevent race conditions

### Cleanup Logic

```go
// Pseudo-code
for each file in dbs directory:
    if file is versioned (matches YYYY-MM-DD pattern):
        if file is not current version:
            if file is not a symlink:
                remove file
                track freed space
```

### Error Handling

- Cleanup failures are non-fatal (logged as warnings)
- Failed deletion of individual files doesn't stop the process
- Database rebuild succeeds even if cleanup fails

## Logging

The server logs cleanup operations:

```
# During cleanup (verbose mode)
Removed old version file: 2024-01-14.tar.gz
Removed old version file: 2024-01-14.json

# After cleanup
Cleanup: removed 2 old version files (freed ~5120 MB)
```

## Benefits

1. **Predictable Storage** - Disk usage stays constant over time
2. **Automatic Management** - No manual intervention required
3. **Fail-Safe** - Cleanup happens after successful rebuild
4. **Transparent** - Detailed logging of cleanup operations
5. **Production-Ready** - Suitable for long-running server deployments

## Trade-offs

### Advantages
- ✅ Prevents storage exhaustion
- ✅ No manual cleanup needed
- ✅ Predictable disk usage
- ✅ Simplified operations

### Limitations
- ⚠️ Cannot roll back to previous versions
- ⚠️ No historical version retention
- ⚠️ Clients must download latest or miss updates

## Alternative Approaches

If you need to keep multiple versions, consider:

1. **Manual Management**: Disable auto-cleanup and manage versions manually
2. **External Storage**: Archive old versions to S3/object storage
3. **Retention Policy**: Modify cleanup logic to keep N most recent versions
4. **Separate Instances**: Run multiple servers for different version streams

## Configuring Retention

Currently, retention is hard-coded to keep only the latest version. To modify this behavior:

### Keep Multiple Versions (Future Enhancement)

To keep the last N versions instead of just the latest, modify `cleanupOldVersions()`:

```go
// Example: Keep last 3 versions
func (s *DBServer) cleanupOldVersions() error {
    // Get all versions
    versions := getVersionsSortedByDate()
    
    // Keep last 3, delete the rest
    if len(versions) > 3 {
        toDelete := versions[:len(versions)-3]
        for _, version := range toDelete {
            deleteVersion(version)
        }
    }
}
```

### Disable Cleanup

To keep all versions (not recommended for production):

1. Comment out the cleanup call in `rebuildDatabases()`:
   ```go
   // if err := s.cleanupOldVersions(); err != nil {
   //     log.Printf("Warning: failed to clean up old versions: %v", err)
   // }
   ```

2. Monitor disk usage manually
3. Implement your own retention policy

## Monitoring

### Check Current Storage Usage

```bash
# Docker
docker exec netcap-dbs-server du -sh /data

# Host
du -sh /path/to/netcap-dbs-server/dbs
```

### List Available Versions

```bash
curl http://localhost:8080/dbs/list
```

Expected response (with auto-cleanup):
```json
{
  "versions": ["2024-01-15"],
  "latest": "2024-01-15",
  "note": "Server is configured to keep only the latest version to optimize storage"
}
```

### Check Cleanup Logs

```bash
# Docker
docker logs netcap-dbs-server | grep -i cleanup

# Output example:
# Cleanup: removed 2 old version files (freed ~5120 MB)
```

## Best Practices

1. **Monitor Disk Space**: Set up alerts for disk usage > 80%
2. **Regular Backups**: Backup the latest version before rebuild
3. **Test Restores**: Periodically test downloading and extracting
4. **Log Rotation**: Rotate server logs to prevent log disk usage
5. **Health Checks**: Monitor the `/health` endpoint

## Troubleshooting

### Storage Still Growing

If storage continues to grow despite cleanup:

1. **Check build artifacts**: Temporary files in `build/` directory
   ```bash
   du -sh /data/netcap-dbs-server/build
   ```

2. **Check logs**: Log files may be accumulating
   ```bash
   du -sh /var/log
   ```

3. **Verify cleanup**: Check server logs for cleanup errors
   ```bash
   grep "cleanup" /var/log/netcap-server.log
   ```

### Old Versions Not Deleted

If old versions remain after rebuild:

1. Check cleanup ran: Look for "Cleanup:" in logs
2. Check file permissions: Server must have write access
3. Check for symlink issues: Ensure symlinks don't prevent deletion
4. Manual cleanup: Safely remove old version files

### Accidental Deletion Recovery

If the current version is accidentally deleted:

1. The server will regenerate it on next rebuild (midnight UTC)
2. Force immediate rebuild: Restart the server
3. No data loss: Databases are regenerated from upstream sources

## Security Considerations

- Cleanup only removes files matching date pattern (YYYY-MM-DD)
- Cannot accidentally delete symlinks or current version
- No risk of deleting build artifacts mid-generation (mutex protected)
- Failures are logged but don't crash the server

## Performance Impact

- Cleanup operation: < 1 second
- Minimal CPU usage during cleanup
- No impact on database generation
- No impact on client downloads

## Conclusion

The automatic storage cleanup feature ensures the database server can run indefinitely without manual intervention or storage concerns. The single-version retention policy is optimal for most use cases where only the latest databases are needed.

For production deployments where historical versions are required, consider implementing external archival or modified retention policies.

