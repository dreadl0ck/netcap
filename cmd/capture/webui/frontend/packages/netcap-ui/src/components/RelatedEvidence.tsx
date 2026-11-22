import { useEffect, useState } from 'react';
import { Alert as MuiAlert, Box, Button, Chip, CircularProgress, Paper, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { useNetcapApi } from '../hooks';
import type { RelatedEvidenceResponse } from '../lib/api';
import { linkKindLabels, type EvidenceRecord, type EvidenceSelector } from '../lib/evidenceLinks';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { translate } from "../lib/i18n";
import { enumLabel } from "../lib/i18n";
import { translate as finalCopyText } from "../lib/i18n";
import { formatNumber } from "../lib/i18n";





const utc = (ns: number) => new Date(ns / 1e6).toISOString().replace('T', ' ').replace('Z', '');
const offset = (ns: number, base: number) => {
  const ms = (ns - base) / 1e6;
  return `${ms >= 0 ? '+' : '−'}${Math.abs(ms) >= 1000 ? `${formatNumber(Math.abs(ms) / 1000, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} s` : `${formatNumber(Math.abs(ms), { minimumFractionDigits: 1, maximumFractionDigits: 1 })} ms`}`;
};
const summary = (record: EvidenceRecord) => (record.summary || []).map(f => `${f.name}=${f.value}`).join('  ');
const kindColor = { 'same-connection': 'default', 'same-flow': 'default', alert: 'error', 'dns-resolution': 'info', 'resolved-connection': 'info' } as const;

/** Records linked to one record across protocols, as a session timeline. */
export function RelatedEvidence({ selector, inputFile }: { selector: EvidenceSelector | null; inputFile?: string }) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const [response, setResponse] = useState<RelatedEvidenceResponse | null>(null);
  const [focus, setFocus] = useState<{ root: string; id: string } | null>(null);
  const key = JSON.stringify(selector);
  const focusedId = focus?.root === key ? focus.id : '';
  useEffect(() => {
    if (!selector) return;
    let current = true;
    setResponse(null);
    api.getRelatedEvidence(focusedId ? { id: focusedId } : selector, inputFile)
      .then(r => { if (current) setResponse(r); })
      .catch(e => { if (current) setResponse({ status: 'unavailable', error: String(e?.message || e) }); });
    return () => { current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, inputFile, focusedId]);
  if (!selector) return null;
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }} data-testid="related-evidence"
      data-learn={i18nText("ui:m_90347340603f4fedca87")}><Typography variant="subtitle2" gutterBottom>{i18nText("ui:m_e88c8ee8b22fc69dbf66")}</Typography>{focusedId && <Button size="small" onClick={() => setFocus(null)}>{i18nText("ui:m_2cfa2f2d9042999a8a8d")}</Button>}{!response && <CircularProgress size={18} />}{response?.status === 'disabled' && <MuiAlert severity="info">{i18nText("ui:m_abd06e2706d1f14bfe76")}</MuiAlert>}{response && response.status !== 'ok' && response.status !== 'disabled' && <Typography variant="body2" color="text.secondary">{response.status === 'not-found' ? i18nText("ui:m_4b0196afb02f9d7627e5") : i18nText("ui:m_42b40aa576df5a1cbed2", { arg0: response.error })}</Typography>}{response?.status === 'ok' && (() => {
        const { result } = response;
        const base = result.session?.first ?? result.target.timestamp;
        const rows = [...result.links.map(l => ({ ...l, target: false })), { kind: 'target' as const, basis: translate("ui:m_a854cfe4a7219952e542"), record: result.target, target: true }]
          .sort((a, b) => a.record.timestamp - b.record.timestamp);
        return (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>{result.scopeStatus === 'verified' && result.target.scope && <Typography variant="body2" color="text.secondary" data-testid="verified-evidence-scope">
                {i18nRichText("ui:m_998181eb2d79443867eb", { arg0: result.target.scope.sensor, arg1: result.target.scope.interfaceIndex, arg2: result.target.scope.vlans.length ? result.target.scope.vlans.join('/') : i18nText("ui:m_0ac115cdb5879b27b85a"), arg3: result.captureId })}
              </Typography>}{['pending', 'overflow', 'missing', 'ambiguous'].includes(result.scopeStatus || '') && <MuiAlert severity="info">{i18nRichText("ui:m_536e7f369e4cc4dfef98", { arg0: result.scopeStatus })}</MuiAlert>}{result.scopeStatus === 'legacy' && <Typography variant="caption" color="text.secondary">{i18nText("ui:m_5f04c217517955b6aa35")}</Typography>}{result.session ? (
              <Typography variant="body2" color="text.secondary">
                {i18nRichText("ui:m_77a7b93759ec1e30d7d6", { arg0: result.session.srcIp, arg1: String(result.session.srcPort), arg2: result.session.dstIp, arg3: String(result.session.dstPort), arg4: utc(result.session.first), arg5: utc(result.session.last) })}
              </Typography>
            ) : <Typography variant="body2" color="text.secondary">{i18nText("ui:m_63d1993acc6bf3fcb6c2")}</Typography>}{result.links.length === 0 && <Typography variant="body2">{i18nText("ui:m_29df7f9e7e203de2b3c5")}</Typography>}{result.links.length > 0 && (
              <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label={i18nText("ui:m_cd2e95f49c5aa885ed50")}><TableHead><TableRow><TableCell>{i18nText("ui:m_dddecd3a256af4e06e01")}</TableCell><TableCell>{i18nText("ui:m_e99ec5e7388df723ccf4")}</TableCell><TableCell>{i18nText("ui:m_9f53618f0ac2911f66b4")}</TableCell><TableCell>{i18nText("ui:m_1dc34a05570354808716")}</TableCell><TableCell>{i18nText("ui:m_0e07624e3854b301c0e2")}</TableCell></TableRow></TableHead><TableBody>{rows.map(row => (
                      <TableRow key={`${row.record.type}-${row.record.ordinal}`} selected={row.target}><TableCell sx={{ whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{utc(row.record.timestamp)}</TableCell><TableCell sx={{ whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{offset(row.record.timestamp, base)}</TableCell><TableCell>{row.target ? <Chip size="small" label={i18nText("ui:m_be76934895ff5a19db76")} color="primary" /> : <Chip size="small" label={finalCopyText(linkKindLabels[row.kind as keyof typeof linkKindLabels])} color={kindColor[row.kind as keyof typeof kindColor]} title={enumLabel(row.basis)} />}</TableCell><TableCell>{!row.target && row.record.id ? <Button size="small" onClick={() => setFocus({ root: key, id: row.record.id! })}
                            aria-label={i18nText("ui:m_1b66eb79473490dd6b6c", { arg0: row.record.type })}>{row.record.type}</Button> : row.record.type}</TableCell><TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>{summary(row.record)}</TableCell></TableRow>
                    ))}</TableBody></Table></Box>
            )}{result.notes.map(note => <Typography key={note} variant="caption" color="text.secondary">{note}</Typography>)}</Box>
        );
      })()}</Paper>
  );
}

export default RelatedEvidence;
