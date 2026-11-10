import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';

const [port, runId, revision] = process.argv.slice(2);
if (!/^423\d\d$/.test(port) || !/^[a-f0-9-]{36}$/.test(runId) || !/^[a-f0-9]{40}$/.test(revision)) throw new Error('Invalid run identity');
const root = resolve('dist');
const types = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png' };
const server = createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname === `/__netcap_e2e/${runId}`) {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ runId, revision }));
  }
  if (/^\/(api|wails|__netcap_e2e)(\/|$)/.test(pathname)) {
    res.writeHead(503); return res.end('Explicit browser mock required');
  }
  const path = resolve(root, `.${pathname}`);
  if (path !== root && !path.startsWith(`${root}/`)) { res.writeHead(403); return res.end(); }
  try {
    const file = extname(path) ? path : resolve(root, 'index.html');
    const data = await readFile(file);
    res.setHeader('Content-Type', types[extname(file)] || 'application/octet-stream');
    res.end(data);
  } catch { res.writeHead(404); res.end(); }
});
server.listen(Number(port), '127.0.0.1', () => console.error(JSON.stringify({ runId, revision, port, pid: process.pid })));
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => server.close(() => process.exit(0)));
