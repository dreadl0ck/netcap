# Netcap Web UI Frontend

`package.json` pins pnpm 9.15.0; `pnpm-lock.yaml` resolves React 19, MUI 7,
React Router 7 and Vite 6. `pnpm run build` builds the canonical shared UI in
`packages/netcap-ui/`, then the Go-embedded production bundle in `dist/`.

| Command (this directory) | Purpose |
| --- | --- |
| `corepack pnpm dev` | Shared-library watcher and Vite development server; `/api` proxies to `localhost:8080` |
| `corepack pnpm run build` | Legal assets, shared UI/types, production bundle |
| `corepack pnpm test` | Vitest |
| `node --test scripts/browser-fixture.test.mjs` | Reject an unrelated server before browser actions |

## Local browser evidence

From the repository root, after building the frontend:

```sh
env -i PATH="$PATH" HOME="$HOME" TMPDIR="$TMPDIR" GOWORK=off \
  CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  NETCAP_INVESTIGATION_BROWSER=1 \
  go test -race -tags nodpi,noyara,nomagika ./cmd/capture/webui \
  -run '^TestInvestigationBrowserPersistence$' -count=1 -v -timeout 120s
```

`PATH` must put a real Node executable before Volta/mise shims: the browser
subprocess has a temporary `HOME`. Set `CHROME_PATH` to an installed browser,
or install the Playwright 1.63.0 browser in `PLAYWRIGHT_BROWSERS_PATH`.

| Check | Evidence boundary |
| --- | --- |
| `TestInvestigationBrowserPersistence` | Synthetic PCAP reader → capture/stream persistence writers → real HTTP → production React; input hash, byte-exact binary/empty/manifest downloads, reload/switch persistence, empty versus unavailable, missing flow-record error |
| `TestInvestigationKnownForeignSessionSelection` | Shareable session reads return only selected evidence; foreign-IP active-session switch rejected; unknown/duplicate selectors and missing manifest fail explicitly |
| `TestCanceledAlertStreamsReleaseOnlyOwnedSlots` | Eight actual SSE clients, ninth rejected, canceled slot reused, persisted alert still readable, all handlers return without shutting down shared server |
| `TestServerStopPreservesUnrelatedListener` | Failed bind/owned shutdown preserve unrelated HTTP identity and release owned port |

Fixtures own ephemeral `127.0.0.1:0` listeners and temporary synthetic data;
`browser-fixture.mjs` verifies output identity, blocks unexpected browser origins
and saves private `netcap-browser-evidence-*` reports/failure traces under the OS
temporary directory. Backend egress is source-audited, not OS-firewalled.

The shared fix belongs in `packages/netcap-ui/src/pages/InvestigationPage.tsx`.
Publishing `@dreadl0ck/netcap-ui` and updating sibling consumers are separate
release tasks. macOS arm64 local evidence does not qualify another OS, full
collector/reassembly, native dialogs, live capture or injection. Next: execute
these mandatory fixtures on an actual Linux/Windows runner; compilation alone
does not qualify that OS.
