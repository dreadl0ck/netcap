import { expect, test } from '@playwright/test';

test('ui-mocked: explicit cross-capture occurrences share table/graph/timeline actions and persist reviewed queries/reports', async ({ page, baseURL }) => {
  const unexpected: string[] = [], errors: string[] = [], resolves: unknown[] = [], queries: any[] = [];
  const bindings = [
    { runId: 'a'.repeat(32), sourceSHA256: 'c'.repeat(64), manifestSHA256: 'e'.repeat(64) },
    { runId: 'b'.repeat(32), sourceSHA256: 'd'.repeat(64), manifestSHA256: 'f'.repeat(64) },
  ];
  const paths = ['/one.pcap', '/two.pcap'];
  const reference = (source: number, ordinal: number) => ({ version: 1, binding: bindings[source], type: 'Connection', file: 'Connection.ncap.gz',
    fileSHA256: '2'.repeat(64), ordinal: String(ordinal), recordSHA256: '1'.repeat(64), timestampNs: `170000000000000000${ordinal}` });
  const occurrences = [[0, 0], [0, 1], [1, 0]].map(([source, ordinal]) => ({ sourceId: bindings[source].runId, reference: reference(source, ordinal), fields: ['SrcIP'], endpoints: ['192.0.2.1', '192.0.2.2'] }));
  let documents: any[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.context().route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    let json: unknown;
    switch (url.pathname) {
      case '/api/status': json = { activeInputFile: paths[0], outputDir: '/owned', isProcessing: false }; break;
      case '/api/files/input': json = paths.map((path, index) => ({ id: String(index), path, name: path.slice(1), isCompleted: true })); break;
      case '/api/version': json = { version: 'ui-mocked' }; break;
      case '/api/menu-counts': json = {}; break;
      case '/api/alerts/stats': json = { totalAlerts: 0, groupCount: 0, bySeverity: {}, byRule: {}, recentAlerts: [] }; break;
      case '/api/dbs/status': json = { satisfied: true, missing: [] }; break;
      case '/api/investigation/capture': json = { runId: bindings[0].runId, status: 'done', inputSHA256: bindings[0].sourceSHA256, configSHA256: '3'.repeat(64), ingressPackets: 3, admittedPackets: 3, queueDrops: 0, truncatedPackets: 0, kernelReceived: null, kernelDrops: null, limitations: ['Retained fixture only'], segments: [] }; break;
      case '/api/investigation/streams': json = []; break;
      case '/api/investigation/health': json = {}; break;
      case '/api/analyst/capabilities': json = { version: 1, occurrenceVersion: 1, catalogueVersion: 1, workspaceVersion: 1, reviewedLogVersion: 1, inspectionVersion: 1 }; break;
      case '/api/analyst/binding': {
        const index = paths.indexOf(url.searchParams.get('inputFile') || ''); expect(index).toBeGreaterThanOrEqual(0); json = bindings[index]; break;
      }
      case '/api/analyst/catalogue': {
        const body = request.postDataJSON(); queries.push(body);
        expect(body.sources).toEqual(paths.map((inputFile, index) => ({ inputFile, binding: bindings[index] })));
        expect(body.query).toEqual({ kind: 'endpoint', value: '192.0.2.1', types: ['Connection'] });
        if (body.expectedSnapshotSHA256) expect(body.expectedSnapshotSHA256).toBe('8'.repeat(64));
        json = { version: 1, snapshotSHA256: '8'.repeat(64), totalOccurrences: 3, query: body.query, sources: bindings.map(binding => ({ id: binding.runId, binding })), coverage: bindings.map(binding => ({ sourceId: binding.runId, type: 'Connection', state: 'complete', records: 2 })), occurrences, novelty: 'observed-in-included-baseline', limitations: ['Explicit included scope only'] }; break;
      }
      case '/api/analyst/resolve': {
        const body = request.postDataJSON(); resolves.push(body.reference);
        expect(body.source).toEqual({ inputFile: paths[0], binding: bindings[0] });
        expect(body.reference).toEqual(reference(0, 0));
        json = { version: 1, reference: body.reference, record: { TimestampFirst: '1700000000000000000', SrcIP: '192.0.2.1' } }; break;
      }
      case '/api/analyst/workspace': {
        const body = request.postDataJSON(); expect(body.source).toEqual({ inputFile: paths[0], binding: bindings[0] });
        if (!body.document) { json = { version: 1, binding: bindings[0], documents }; break; }
        const previous = documents.find(doc => doc.id === body.document.id);
        if (body.document.kind === 'query') expect(body.document.catalogueSnapshotSHA256).toBe('8'.repeat(64));
        expect(body.expectedRevision).toBe(previous?.revision ?? 0);
        if (body.document.review === 'reviewed') {
          expect(previous).toBeDefined(); expect(body.document.body).toBe(previous.body); expect(body.document.reviewer).toBe('Fixture analyst');
        }
        const next = { ...body.document, id: previous?.id || `document-${documents.length + 1}`, revision: (previous?.revision ?? 0) + 1, updatedAt: '2026-11-08T00:00:00Z' };
        documents = [...documents.filter(doc => doc.id !== next.id), next]; json = next; break;
      }
      default: unexpected.push(url.pathname); return route.abort();
    }
    return route.fulfill({ json });
  });
  await page.goto('/investigation-evidence');
  await page.getByRole('checkbox', { name: 'one.pcap', exact: true }).check();
  await page.getByRole('checkbox', { name: 'two.pcap', exact: true }).check();
  await page.getByLabel('Exact indicator / selected text').fill('192.0.2.1');
  await page.getByRole('button', { name: 'Search included captures', exact: true }).click();
  await expect(page.getByText('Novelty: observed-in-included-baseline · 3 retained occurrences')).toBeVisible();
  await page.getByRole('button', { name: 'Resolve table occurrence 0', exact: true }).click();
  await expect(page.getByText(/Verified occurrence \(record preview/)).toBeVisible();
  await page.getByRole('combobox', { name: 'Occurrence view' }).click(); await page.getByRole('option', { name: 'graph', exact: true }).click();
  await expect(page.getByRole('img', { name: 'Content-bound occurrence graph' })).toBeVisible();
  await page.getByRole('button', { name: 'Resolve graph occurrence 0', exact: true }).click();
  await page.getByRole('combobox', { name: 'Occurrence view' }).click(); await page.getByRole('option', { name: 'timeline', exact: true }).click();
  await page.getByRole('button', { name: 'Resolve timeline occurrence 0', exact: true }).click();
  await expect.poll(() => resolves.length).toBe(3);
  expect(resolves).toEqual([reference(0, 0), reference(0, 0), reference(0, 0)]);
  await page.getByLabel('Document title', { exact: true }).fill('Saved peer query');
  await page.getByLabel('Report / query notes', { exact: true }).fill('Explicit two-capture baseline; retained evidence only.');
  await page.getByRole('button', { name: 'Save draft', exact: true }).click();
  await expect(page.getByText('Document revision 1 · draft')).toBeVisible();
  await page.getByLabel('Reviewer', { exact: true }).fill('Fixture analyst');
  await page.getByRole('button', { name: 'Mark persisted document reviewed', exact: true }).click();
  await expect(page.getByText('Document revision 2 · reviewed')).toBeVisible();
  await page.getByRole('button', { name: 'New document', exact: true }).click();
  await page.getByRole('combobox', { name: 'Document kind' }).click(); await page.getByRole('option', { name: 'report', exact: true }).click();
  await page.getByLabel('Document title', { exact: true }).fill('Peer report');
  await page.getByLabel('Report / query notes', { exact: true }).fill('Draft finding references the verified primary occurrence.');
  await page.getByRole('button', { name: 'Save draft', exact: true }).click();
  await expect(page.getByText('Document revision 1 · draft')).toBeVisible();
  await page.getByRole('button', { name: 'Mark persisted document reviewed', exact: true }).click();
  await expect(page.getByText('Document revision 2 · reviewed')).toBeVisible();
  await page.reload();
  await page.getByRole('checkbox', { name: 'one.pcap', exact: true }).check();
  await page.getByRole('button', { name: 'Load saved workspace', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Saved peer query · r2 · reviewed', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Peer report · r2 · reviewed', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Rerun saved query with stored binding', exact: true }).click();
  await expect.poll(() => queries.length).toBe(2);
  expect(queries[1].sources).toEqual(queries[0].sources);
  expect(documents[1].references).toEqual([reference(0, 0)]);
  expect(unexpected).toEqual([]); expect(errors).toEqual([]);
});

test('ui-mocked: incomplete analyst capabilities never fall back to an active-capture query', async ({ page, baseURL }) => {
  const unexpected: string[] = [], mutations: string[] = [];
  await page.context().route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== baseURL) { unexpected.push(url.href); return route.abort(); }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    let json: unknown;
    switch (url.pathname) {
      case '/api/status': json = { activeInputFile: '/one.pcap', outputDir: '/owned', isProcessing: false }; break;
      case '/api/files/input': json = [{ id: 'one', path: '/one.pcap', name: 'one.pcap', isCompleted: true }]; break;
      case '/api/version': json = { version: 'ui-mocked' }; break;
      case '/api/menu-counts': json = {}; break;
      case '/api/alerts/stats': json = { totalAlerts: 0, groupCount: 0, bySeverity: {}, byRule: {}, recentAlerts: [] }; break;
      case '/api/dbs/status': json = { satisfied: true, missing: [] }; break;
      case '/api/investigation/capture': json = { runId: 'one', status: 'done', configSHA256: '', limitations: [], segments: [] }; break;
      case '/api/investigation/streams': json = []; break;
      case '/api/investigation/health': json = {}; break;
      case '/api/analyst/capabilities': json = { version: 1, occurrenceVersion: 1, catalogueVersion: 1 }; break;
      default: mutations.push(url.pathname); return route.abort();
    }
    return route.fulfill({ json });
  });
  await page.goto('/investigation-evidence');
  await page.getByRole('checkbox', { name: 'one.pcap', exact: true }).check();
  await page.getByRole('button', { name: 'Search included captures', exact: true }).click();
  await expect(page.getByText('This backend does not support the complete analyst workspace contract.')).toBeVisible();
  expect(mutations).toEqual([]); expect(unexpected).toEqual([]);
});
