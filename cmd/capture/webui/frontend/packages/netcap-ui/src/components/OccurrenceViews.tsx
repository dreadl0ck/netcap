import { useEffect, useState } from 'react';
import { Box, Button, MenuItem, Stack, TextField, Typography } from '@mui/material';
import type { AnalystOccurrence, CatalogueResult } from '../lib/analyst';

export default function OccurrenceViews({ result, busy, resolve }: { result: CatalogueResult; busy: boolean; resolve: (item: AnalystOccurrence) => void }) {
  const [mode, setMode] = useState('table'), [page, setPage] = useState(0);
  useEffect(() => setPage(0), [result]);
  const ordered = mode === 'timeline' ? [...result.occurrences].sort((a, b) => {
    const x = BigInt(a.reference.timestampNs), y = BigInt(b.reference.timestampNs); return x < y ? -1 : x > y ? 1 : 0;
  }) : result.occurrences;
  const offset = page * 100, shown = ordered.slice(offset, offset + 100);
  // Equal addresses in separate captures must not silently become one host node.
  const nodeKey = (item: AnalystOccurrence, ip: string) => JSON.stringify([item.sourceId, ip]);
  const nodes = [...new Set(shown.flatMap(item => (item.endpoints ?? []).map(ip => nodeKey(item, ip))))];
  const point = (key: string) => { const angle = nodes.indexOf(key) * Math.PI * 2 / Math.max(1, nodes.length); return { x: 300 + 220 * Math.cos(angle), y: 220 + 160 * Math.sin(angle) }; };
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }));
    try { const link = document.createElement('a'); link.href = url; link.download = 'netcap-catalogue.json'; link.click(); }
    finally { URL.revokeObjectURL(url); }
  };
  return <Stack spacing={1}>
    <TextField select label="Occurrence view" value={mode} onChange={event => { setMode(event.target.value); setPage(0); }}>
      {['table', 'graph', 'timeline'].map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}
    </TextField>
    <Typography variant="caption">Showing {shown.length ? offset + 1 : 0}–{offset + shown.length} of {ordered.length} exact references. Address nodes are capture-qualified values, not verified host identities. Interface/VLAN attribution requires the underlying evidence.</Typography>
    <Stack direction="row" spacing={1}>
      <Button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous occurrence page</Button>
      <Button disabled={offset + 100 >= ordered.length} onClick={() => setPage(page + 1)}>Next occurrence page</Button>
      <Button onClick={download}>Export complete included catalogue</Button>
    </Stack>
    {mode === 'graph' ? <>
      <Typography variant="caption">Observed endpoint pairs for this page; layout is schematic. No inferred joins between captures or verified host/account ownership.</Typography>
      <Box component="svg" viewBox="0 0 600 440" role="img" aria-label="Content-bound occurrence graph" sx={{ width: '100%', maxHeight: 440 }}>
        <metadata>{JSON.stringify({ query: result.query, sources: result.sources, coverage: result.coverage, limitations: result.limitations, page, references: shown.map(item => item.reference) })}</metadata>
        <text x={8} y={430} fill="currentColor" fontSize={10}>Observed record endpoints; schematic layout; included captures only; page {page + 1}</text>
        {shown.map((item, index) => {
          if (!item.endpoints || item.endpoints.length < 2) return null;
          const a = point(nodeKey(item, item.endpoints[0])), b = point(nodeKey(item, item.endpoints[1]));
          return <g key={index} onClick={() => resolve(item)} data-occurrence={JSON.stringify(item.reference)}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="currentColor" strokeWidth={4}><title>{item.reference.type} #{item.reference.ordinal}</title></line>
          </g>;
        })}
        {nodes.map(key => { const p = point(key), [source, ip] = JSON.parse(key) as [string, string]; return <g key={key}>
          <title>{source} / {ip}</title><circle cx={p.x} cy={p.y} r={8} fill="currentColor" />
          <text x={p.x} y={p.y - 12} textAnchor="middle" fill="currentColor" fontSize={10}>{source.slice(0, 8)} / {ip}</text>
        </g>; })}
      </Box>
      {shown.map((item, index) => <Button key={index} disabled={busy} onClick={() => resolve(item)}>Resolve graph occurrence {offset + index}</Button>)}
    </> : <Box component={mode === 'timeline' ? 'ol' : 'div'}>
      {shown.map((item, index) => <Box key={`${item.sourceId}:${item.reference.type}:${item.reference.fileSHA256}:${item.reference.ordinal}`} component={mode === 'timeline' ? 'li' : 'div'}>
        <Button disabled={busy} onClick={() => resolve(item)}>{mode === 'timeline' ? 'Resolve timeline' : 'Resolve table'} occurrence {offset + index}</Button>
        {item.sourceId} · {item.reference.type} #{item.reference.ordinal} · {item.reference.timestampNs} ns · {item.endpoints?.join(' → ')}
      </Box>)}
    </Box>}
  </Stack>;
}
