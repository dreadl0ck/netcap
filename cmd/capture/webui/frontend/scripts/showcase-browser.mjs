import assert from 'node:assert/strict';
import { chromium, expect } from '@playwright/test';

const [, , base, version, captures] = process.argv;
assert.match(base, /^http:\/\/127\.0\.0\.1:\d+$/);
const rows = JSON.parse(captures);
const [mail, smb, partial] = ['mail.pcap', 'smb.pcap', 'arp-dns-eth-icmp-ip-udp-goodhttp-gooddns.pcapng'].map(name => rows[name]);
assert(mail?.sessionId && smb?.sessionId && partial?.sessionId);

const browser = await chromium.launch({ channel: 'chrome', timeout: 25_000, args: ['--disable-background-networking'] });
try {
  const blocked = [];
  async function newVisitor() {
    const context = await browser.newContext({ baseURL: base, serviceWorkers: 'block' });
    context.setDefaultNavigationTimeout(15_000);
    context.setDefaultTimeout(10_000);
    await context.route('**/*', (route) => {
      if (new URL(route.request().url()).origin === base) return route.continue();
      blocked.push(new URL(route.request().url()).origin);
      return route.abort();
    });
    const backend = await context.request.get('/api/version');
    assert.deepEqual(await backend.json(), JSON.parse(version), 'wrong local service');
    return context;
  }
  const [visitorA, visitorB] = await Promise.all([newVisitor(), newVisitor()]);
  const [pageA, pageB] = await Promise.all([visitorA.newPage(), visitorB.newPage()]);
  const errors = [];
  for (const page of [pageA, pageB]) page.on('pageerror', err => errors.push(err.message));
  await Promise.all([pageA.goto(`/view/${mail.sessionId}`), pageB.goto(`/view/${smb.sessionId}`)]);
  await Promise.all([pageA, pageB].map(page => page.getByRole('button', { name: 'Start exploring' }).click()));
  await expect(pageA.getByRole('heading', { name: 'Cleartext email authentication' })).toBeVisible();
  await expect(pageB.getByRole('heading', { name: 'Windows file sharing in a lab' })).toBeVisible();
  await pageA.goto(`/pcaps?sessionId=${mail.sessionId}`);
  await pageA.getByRole('cell', { name: partial.name, exact: false }).first().click();
  await expect(pageA).toHaveURL(new RegExp(`sessionId=${partial.sessionId}`));
  await expect(pageA.getByRole('status').filter({ hasText: 'Partial packet coverage' })).toBeVisible();
  await pageB.reload();
  await expect(pageB.getByRole('heading', { name: 'Windows file sharing in a lab' })).toBeVisible();
  const noSelection = await visitorB.request.get('/api/status');
  assert.equal((await noSelection.json()).sessionId, undefined);

  const frame = Buffer.from('ffffffffffff02000000000108060001080006040001020000000001c0000201000000000000c0000202', 'hex');
  const header = Buffer.from('d4c3b2a1020004000000000000000000ffff00000100000000000000000000000000000000000000', 'hex');
  header.writeUInt32LE(frame.length, 32);
  header.writeUInt32LE(frame.length, 36);
  async function upload(context, name) {
    const response = await context.request.post('/api/upload', { multipart: { file: { name, mimeType: 'application/octet-stream', buffer: Buffer.concat([header, frame]) } } });
    assert(response.ok(), `upload ${name}: HTTP ${response.status()}`);
    return (await response.json()).sessionId;
  }
  const [uploadA, uploadB] = await Promise.all([upload(visitorA, 'visitor-a.pcap'), upload(visitorB, 'visitor-b.pcap')]);
  assert(uploadA && uploadB && uploadA !== uploadB);
  for (const [visitor, own, other] of [[visitorA, uploadA, uploadB], [visitorB, uploadB, uploadA]]) {
    await expect.poll(async () => (await (await visitor.request.get(`/api/status/${own}`)).json()).status, { timeout: 40_000 }).toBe('completed');
    const listed = await (await visitor.request.get('/api/files/input')).json();
    assert(listed.some(row => row.sessionId === own));
    assert(!listed.some(row => row.sessionId === other));
    assert.equal((await visitor.request.get(`/api/audit-stats?sessionId=${other}`)).status(), 403);
    assert.equal((await visitor.request.get(`/api/error-log/${other}`)).status(), 404);
    assert.equal((await visitor.request.get(`/api/progress/${other}`)).status(), 404);
  }
  assert.deepEqual(errors, []);
  assert.deepEqual(blocked, []);
  console.log(JSON.stringify({ browser: 'two same-IP contexts: capture switching, reload and concurrent upload isolation passed' }));
} finally {
  await browser.close();
}
