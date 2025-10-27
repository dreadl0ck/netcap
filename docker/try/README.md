# Netcap Try Service - Docker Setup

A Docker container for running the Netcap Try service with file upload and analysis capabilities.

## Quick Start

```bash
# Build and start the service
cd docker/try
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

## Access the Service

Once the service is running, you can access it at:

- **From the same machine:** http://localhost:7070
- **From another machine:** http://YOUR_HOST_IP:7070

## Configuration

The service can be configured through environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `NC_DATA_DIR` | `/data/netcap-try` | Directory for storing uploads and results |
| `NC_HTTP` | `0.0.0.0:7070` | HTTP server bind address and port |
| `NC_DPI` | `true` | Enable Deep Packet Inspection (not available in nodpi builds) |
| `NC_MAX_FILE_SIZE` | `52428800` | Maximum upload file size in bytes (50MB) |
| `NC_MAX_ANALYSIS_HOUR` | `2` | Maximum analyses per hour per IP |
| `NC_SESSION_EXPIRY` | `60` | Session expiry time in minutes |
| `NC_CLEANUP_INTERVAL` | `10` | Cleanup interval in minutes |

## Troubleshooting

### Web Interface Not Reachable

If the service is running but the web interface is not reachable:

1. **Check if the container is running:**
   ```bash
   docker ps | grep netcap-try
   ```

2. **Verify the port is bound on the host:**
   ```bash
   # On macOS/Linux
   lsof -i :7070
   
   # Or use netstat
   netstat -an | grep 7070
   ```

3. **Check container logs for errors:**
   ```bash
   docker-compose logs netcap-try
   ```

4. **Test from inside the container:**
   ```bash
   docker exec -it netcap-try curl http://localhost:7070/health
   ```
   
   If this works but external access doesn't, it's a network/port binding issue.

5. **Check Docker port mapping:**
   ```bash
   docker port netcap-try
   ```
   
   Should show: `7070/tcp -> 0.0.0.0:7070`

6. **Verify firewall settings:**
   - Ensure port 7070 is not blocked by your firewall
   - On macOS: System Preferences → Security & Privacy → Firewall
   - On Linux: Check `iptables` or `firewalld`

7. **Try accessing with explicit IP:**
   ```bash
   # Get your machine's IP
   ifconfig | grep "inet "
   
   # Try accessing with the IP
   curl http://YOUR_IP:7070/health
   ```

### Container Keeps Restarting

Check the logs for errors:
```bash
docker-compose logs netcap-try
```

Common issues:
- Database download failure (temporary network issue)
- Insufficient disk space
- Memory limits too restrictive

### Slow Performance

The service has resource limits configured. To adjust them, edit `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'      # Increase CPU limit
      memory: 8G       # Increase memory limit
```

Then restart the service:
```bash
docker-compose down
docker-compose up -d
```

## Network Configuration

### Using with Traefik (Recommended for Production)

For Traefik deployments, use `docker-compose.traefik.yml`:

```bash
docker-compose -f docker-compose.traefik.yml up -d
```

**Key requirements for Traefik:**

1. **Container must be on the `proxy` network** (or whatever network Traefik monitors)
2. **Must have `traefik.enable=true` label** (Traefik won't detect it otherwise)
3. **Must bind to `0.0.0.0:7070`** so Traefik can reach it
4. **No direct port mapping needed** (Traefik handles all routing)

Common Traefik issues:

- **Container not reachable but healthy**: Container not on the `proxy` network
- **Traefik doesn't detect service**: Missing `traefik.enable=true` label
- **502 Bad Gateway**: Application not binding to `0.0.0.0` (binding to `localhost` only)
- **Certificate errors**: Check `certresolver` name matches your Traefik config

Verify Traefik can reach the container:
```bash
# Check if container is on proxy network
docker inspect netcap-try --format='{{json .NetworkSettings.Networks}}' | grep proxy

# Check Traefik logs
docker logs traefik | grep netcap-try

# Test from Traefik's network
docker run --rm --network=proxy curlimages/curl:latest curl http://netcap-try:7070/health
```

### Using with Nginx

Example nginx configuration:
```nginx
location / {
    proxy_pass http://localhost:7070;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Increase timeout for large uploads
    proxy_read_timeout 300;
    proxy_send_timeout 300;
}
```

### General Reverse Proxy Requirements

The service works with any reverse proxy and includes:

- **CORS enabled:** Service already has CORS headers configured
- **WebSocket support:** Not required for this service
- **Client IP forwarding:** Service reads `X-Forwarded-For` and `X-Real-IP` headers

### Custom Network

The service uses a dedicated bridge network (`netcap-try`). To connect other containers:

```yaml
services:
  my-service:
    networks:
      - netcap-try

networks:
  netcap-try:
    external: true
```

## Data Persistence

Analysis results and uploads are stored in a Docker volume:

```bash
# Inspect the volume
docker volume inspect try_netcap-try-data

# Backup the volume
docker run --rm -v try_netcap-try-data:/data -v $(pwd):/backup alpine tar czf /backup/netcap-try-backup.tar.gz /data

# Restore the volume
docker run --rm -v try_netcap-try-data:/data -v $(pwd):/backup alpine tar xzf /backup/netcap-try-backup.tar.gz -C /
```

## Health Checks

The service has a built-in health check that runs every 30 seconds:

```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' netcap-try
```

Possible statuses:
- `starting`: Container is starting up (up to 120 seconds)
- `healthy`: Service is responding correctly
- `unhealthy`: Health check failed 3 times in a row

## Logs

View different log levels:

```bash
# Follow all logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100

# Only errors
docker-compose logs | grep -i error
```

## Database Management

The service automatically downloads required databases on first startup. This may take a few minutes.

To manually update databases:
```bash
docker exec -it netcap-try netcap util -download-dbs
```

Database location inside container: `/home/netcap/.config/netcap/dbs`

## Development

### Rebuild After Code Changes

```bash
# Rebuild and restart
docker-compose build --no-cache
docker-compose up -d

# Or use the build script
cd ../..
./zeus/scripts/build-try-server.sh
```

### Interactive Shell

```bash
docker exec -it netcap-try sh
```

## Security Considerations

1. **Rate Limiting:** The service has built-in rate limiting (max analyses per hour)
2. **File Size Limits:** Upload size is limited to prevent DoS attacks
3. **Non-Root User:** Container runs as user `netcap` (UID 1000)
4. **Session Expiry:** Old sessions are automatically cleaned up
5. **Network Isolation:** Uses a dedicated Docker network

For production use, consider:
- Running behind a reverse proxy with TLS
- Implementing authentication
- Setting up monitoring and alerting
- Regular backups of analysis data

## Support

For issues or questions:
- GitHub Issues: https://github.com/dreadl0ck/netcap/issues
- Documentation: https://docs.netcap.io
