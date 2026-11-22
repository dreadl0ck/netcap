import { useEffect, useState } from 'react';
import { Box, Button, MenuItem, Stack, TextField, Typography } from '@mui/material';
import type { AnalystOccurrence, CatalogueResult } from '../lib/analyst';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";


export default function OccurrenceViews({ result, busy, resolve }: { result: CatalogueResult; busy: boolean; resolve: (item: AnalystOccurrence) => void }) {
  const __uiLocale = useUILocale();
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
  return <Stack spacing={1}><TextField select label={i18nText("ui:m_2da11f715da84361e701")} value={mode} onChange={event => { setMode(event.target.value); setPage(0); }}>{['table', 'graph', 'timeline'].map(value => <MenuItem key={value} value={value}>{i18nText(value)}</MenuItem>)}</TextField><Typography variant="caption">{i18nRichText("ui:m_9df025d57938d52495fa", { arg0: shown.length ? offset + 1 : 0, arg1: offset + shown.length, arg2: ordered.length })}</Typography><Stack direction="row" spacing={1}><Button disabled={page === 0} onClick={() => setPage(page - 1)}>{i18nText("ui:m_b0bf7918dbbec90460ab")}</Button><Button disabled={offset + 100 >= ordered.length} onClick={() => setPage(page + 1)}>{i18nText("ui:m_2314dad0cb74179a9a39")}</Button><Button onClick={download}>{i18nText("ui:m_f04e32743cd4bc20e4dd")}</Button></Stack>{mode === 'graph' ? <><Typography variant="caption">{i18nText("ui:m_3604edb1cfe85c2710c6")}</Typography><Box component="svg" viewBox="0 0 600 440" role="img" aria-label={i18nText("ui:m_5cf32cb20f1bff333f31")} sx={{ width: '100%', maxHeight: 440 }}><metadata>{JSON.stringify({ query: result.query, sources: result.sources, coverage: result.coverage, limitations: result.limitations, page, references: shown.map(item => item.reference) })}</metadata><text x={8} y={430} fill="currentColor" fontSize={10}>{i18nRichText("ui:m_fb342bc1e3531c7642fd", { arg0: page + 1 })}</text>{shown.map((item, index) => {
          if (!item.endpoints || item.endpoints.length < 2) return null;
          const a = point(nodeKey(item, item.endpoints[0])), b = point(nodeKey(item, item.endpoints[1]));
          return <g key={index} onClick={() => resolve(item)} data-occurrence={JSON.stringify(item.reference)}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="currentColor" strokeWidth={4}><title>{item.reference.type}#{item.reference.ordinal}</title></line></g>;
        })}{nodes.map(key => { const p = point(key), [source, ip] = JSON.parse(key) as [string, string]; return <g key={key}><title>{source}/ {ip}</title><circle cx={p.x} cy={p.y} r={8} fill="currentColor" /><text x={p.x} y={p.y - 12} textAnchor="middle" fill="currentColor" fontSize={10}>{source.slice(0, 8)}/ {ip}</text></g>; })}</Box>{shown.map((item, index) => <Button key={index} disabled={busy} onClick={() => resolve(item)}>{i18nRichText("ui:m_28b9664b34732a1b96de", { arg0: offset + index })}</Button>)}</> : <Box component={mode === 'timeline' ? 'ol' : 'div'}>{shown.map((item, index) => <Box key={`${item.sourceId}:${item.reference.type}:${item.reference.fileSHA256}:${item.reference.ordinal}`} component={mode === 'timeline' ? 'li' : 'div'}><Button disabled={busy} onClick={() => resolve(item)}>{i18nRichText("ui:m_cbb7759771fbfc70687f", { arg0: mode === 'timeline' ? i18nText("ui:m_ee8851859113fa0fd90d") : i18nText("ui:m_6c5ea51d99ecd109b24c"), arg1: offset + index })}</Button>
        {i18nRichText("ui:m_37945c13ee86190f7acf", { arg0: item.sourceId, arg1: item.reference.type, arg2: String(item.reference.ordinal), arg3: String(item.reference.timestampNs), arg4: item.endpoints?.join(' → ') })}
      </Box>)}</Box>}</Stack>;
}
