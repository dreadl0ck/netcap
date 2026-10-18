import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { qualify } from './browser-fixture.mjs';

test('unknown fixture identity fails before any browser action and retains evidence', async t => {
  const server = createServer((request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ outputDir: 'unrelated-fixture' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const evidence = mkdtempSync(path.join(tmpdir(), 'netcap-browser-negative-'));
  for (const [name, value] of Object.entries({ NETCAP_BROWSER_OUTPUT: 'owned-fixture', NETCAP_BROWSER_EVIDENCE: evidence })) {
    const previous = process.env[name];
    process.env[name] = value;
    t.after(() => { if (previous === undefined) delete process.env[name]; else process.env[name] = previous; });
  }
  let acted = false;
  await assert.rejects(qualify(`http://127.0.0.1:${server.address().port}`, () => { acted = true; }), /unknown fixture server/);
  assert.equal(acted, false);
  const report = JSON.parse(readFileSync(path.join(evidence, 'report.json'), 'utf8'));
  assert.equal(report.passed, false);
  assert.match(report.error, /unknown fixture server/);
});
