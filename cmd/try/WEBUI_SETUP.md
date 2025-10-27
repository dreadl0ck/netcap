# WebUI Setup for Try Service

The try service uses the same webUI frontend from the capture tool to allow users to explore their analysis results.

## Quick Setup

Since the frontend is already built in the capture webUI, you just need to copy it:

```bash
# From the project root
mkdir -p cmd/try/webui/frontend
cp -r cmd/capture/webui/frontend/out cmd/try/webui/frontend/
```

This copies the pre-built static frontend assets to the try service.

## Rebuild (if needed)

If you need to rebuild the frontend:

```bash
# Build the capture webUI frontend
cd cmd/capture/webui/frontend
npm install
npm run build

# Copy to try service
cd ../../../..
cp -r cmd/capture/webui/frontend/out cmd/try/webui/frontend/
```

## Automatic Build Integration

You can also create a symlink instead of copying:

```bash
# From the project root
mkdir -p cmd/try/webui/frontend
cd cmd/try/webui/frontend
ln -s ../../../capture/webui/frontend/out out
```

This way, any updates to the capture webUI frontend are automatically available to the try service.

## How It Works

1. The try service embeds the frontend assets at build time using `go:embed`
2. The webUI handlers adapt the capture webUI API to work with session-based uploads
3. Users can upload files, and once analysis completes, explore the results using the full capture webUI
4. Multiple sessions can be managed and switched between

## Development Mode

For development with hot-reload:

```bash
# Terminal 1: Run Next.js dev server
cd cmd/capture/webui/frontend
npm run dev

# Terminal 2: Run try service pointing to dev server
# (requires updating webui/server.go to support assets path)
net try -http :7070
```

## Verification

After copying the frontend assets, verify they're in place:

```bash
ls -la cmd/try/webui/frontend/out/
# Should see: index.html, _next/, etc.
```

Then rebuild netcap:

```bash
zeus install
```

The try service will now serve the full webUI interface!

