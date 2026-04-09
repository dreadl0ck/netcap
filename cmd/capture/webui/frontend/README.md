# Netcap Web UI Frontend

This is the Next.js-based frontend for the Netcap Web UI.

## Development

```bash
pnpm install
pnpm run dev
```

Open [http://localhost:3000](http://localhost:3000) to see the result.

## Building for Production

```bash
pnpm run build
```

This creates a static export in the `out/` directory which is embedded into the Go binary.

## Tech Stack

- **Next.js 14**: React framework with static export
- **Material-UI 5**: Component library
- **TypeScript**: Type safety
- **SWR**: Data fetching and caching

## Project Structure

```
src/
├── components/       # Reusable components
│   └── Layout.tsx   # Main layout with navigation
├── lib/             # Utilities and API client
│   └── api.ts       # API client and helpers
└── pages/           # Next.js pages
    ├── _app.tsx     # App wrapper with theme
    ├── _document.tsx # Document wrapper
    ├── index.tsx    # Dashboard
    ├── files.tsx    # Input files viewer
    ├── audit.tsx    # Audit records browser
    └── logs.tsx     # Log viewer
```

## Customization

### Theme

Edit `src/pages/_app.tsx` to customize the Material-UI theme:

```typescript
const theme = createTheme({
  palette: {
    mode: 'dark', // or 'light'
    primary: {
      main: '#00bcd4', // Change primary color
    },
  },
});
```

### API Endpoint

The API base URL is automatically set to `/api` for production. For development with a different backend, edit `src/lib/api.ts`:

```typescript
const API_BASE = 'http://localhost:8080/api';
```

