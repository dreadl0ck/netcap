import { defineConfig } from '@playwright/test';
import { createHash, randomInt, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const port = Number(process.env.NETCAP_E2E_PORT ?? randomInt(42300, 42400));
if (!Number.isInteger(port) || port < 42300 || port > 42399) throw new Error('NETCAP_E2E_PORT must be 42300–42399');
process.env.NETCAP_E2E_PORT = String(port);
const runId = randomUUID();
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const worktreeStatus = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' });
const diffSHA256 = createHash('sha256').update(execFileSync('git', ['diff', 'HEAD'])).digest('hex');

// ui-mocked: built static frontend only; no backend or developer dotenv files.
export default defineConfig({
  testDir: './e2e', workers: 1, retries: 0, timeout: 30_000,
  metadata: { executionClass: 'ui-mocked', runId, revision, worktreeStatus, diffSHA256 },
  use: {
    baseURL: `http://127.0.0.1:${port}`, browserName: 'chromium', channel: 'chrome',
    serviceWorkers: 'block', trace: 'retain-on-failure', screenshot: 'only-on-failure',
  },
  webServer: {
    command: `node e2e/server.mjs ${port} ${runId} ${revision}`,
    url: `http://127.0.0.1:${port}/__netcap_e2e/${runId}`,
    reuseExistingServer: false, timeout: 10_000,
  },
});
