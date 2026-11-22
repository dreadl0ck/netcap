import { Accordion, AccordionSummary, AccordionDetails, Box, Button, Chip, Stack, Table, TableBody, TableCell, TableHead, TableRow, Tooltip, Typography } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

import { useNetcapApi, useNetcapRouter } from '../hooks';
import { useNetcapConfig } from '../providers';
import { behaviorRequest, behaviorSelection, factLabel, scopeLabel } from '../lib/behavior';
import type { BehaviorObservation } from '../lib/behavior';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { renderError } from "../lib/i18n";




interface AssetContext {
  asset: string;
  records: { id: string; observation: BehaviorObservation; label?: { name: string; role?: string; notes?: string };
    direction: string; prefixes?: string[]; prefixesTruncated?: boolean }[];
  totalRecords: number;
  truncated: boolean;
}

export default function BehaviorAssetContext({ asset }: { asset: string }) {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const router = useNetcapRouter();
  const config = useNetcapConfig();
  const { data: status } = useSWR('status', () => api.getStatus(), { refreshInterval: 1000 });
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const url = `${config.apiBaseUrl}/behavior/asset${selection || '?'}${selection ? '&' : ''}asset=${encodeURIComponent(asset)}`;
  const { data, error } = useSWR<AssetContext>(status && asset ? url : null,
    () => behaviorRequest(config.fetch ?? fetch, url), { refreshInterval: 5000, keepPreviousData: false });
  return <Accordion disableGutters variant="outlined" sx={{ my: 1, '&:before': { display: 'none' } }}><AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ '&:hover': { bgcolor: 'action.hover' }, '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2 } }}><Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap', gap: 0.5 }}><Typography variant="subtitle2">{i18nText("ui:m_e9af8bbfc96028c1a8c0")}</Typography><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{asset}</Typography>{data && <Chip size="small" variant="outlined" label={i18nText("ui:m_8721c05f8f944cd10769", { arg0: data.totalRecords })} />}</Stack></AccordionSummary><AccordionDetails role="region" aria-label={i18nText("ui:m_0278d0f6f4f90a1d7b93", { arg0: asset })} sx={{ pt: 0 }}><Stack spacing={1}>{error && <Typography variant="body2" color="text.secondary">{renderError(error)}</Typography>}{!data && !error && <Typography variant="body2" color="text.secondary">{i18nText("ui:m_db583b31e8d5f3ff3568")}</Typography>}{data && <>{data.truncated && <Typography variant="caption" color="text.secondary">{i18nRichText("ui:m_e93509afe08562d47dcb", { arg0: data.records.length, arg1: data.totalRecords })}</Typography>}{data.records.length === 0 ? <Typography variant="body2" color="text.secondary">{i18nText("ui:m_4193035b58df2a800c12")}</Typography> : <Box sx={{ overflowX: 'auto' }}><Table size="small" aria-label={i18nText("ui:m_3b2c0930473d40d29361", { arg0: asset })}><TableHead><TableRow><TableCell>{i18nText("ui:m_bfc5704607845bd69567")}</TableCell><TableCell>{i18nText("ui:m_48f5b33a96be6e151603")}</TableCell><TableCell>{i18nText("ui:m_4113167561ccea5b6c6b")}</TableCell><TableCell>{i18nText("ui:m_f076d4d5af9ae08ee32e")}</TableCell></TableRow></TableHead><TableBody>{data.records.map(record => <TableRow key={record.id}><TableCell><Typography variant="caption" color="text.secondary">{record.observation.fact.kind === 'edge' ? i18nText("ui:m_72f4572fd93b9ca38ff6") : record.observation.fact.kind}</Typography><Typography variant="body2">{factLabel(record.observation.fact)}</Typography>{record.label?.name && <Typography variant="caption">{record.label.name}{record.label.role ? ` · ${record.label.role}` : ''}</Typography>}{record.label?.notes && <Typography variant="caption" display="block">{record.label.notes}</Typography>}</TableCell><TableCell><Tooltip title={record.prefixes?.length ? i18nText("ui:m_d170b44e2b08d6a7414c", { arg0: record.prefixes.join(', '), arg1: record.prefixesTruncated ? i18nText("ui:m_2ec34d17d09025d06409") : '' }) : i18nText("ui:m_85bc005de197b3c362d8")}><Typography variant="body2">{record.direction === 'unknown' ? i18nText("ui:m_2f1ac5f44673922d2bf2") : record.direction}</Typography></Tooltip></TableCell><TableCell><Tooltip title={scopeLabel(record.observation.fact.scope)}><Typography variant="caption">{record.observation.fact.provenance || i18nText("ui:m_36d1bf28e0e7933dc454")}</Typography></Tooltip></TableCell><TableCell sx={{ whiteSpace: 'nowrap' }}><Typography variant="caption" display="block">{new Date(record.observation.firstSeen / 1e6).toLocaleString(getUILocale())}</Typography><Typography variant="caption" color="text.secondary">{new Date(record.observation.lastSeen / 1e6).toLocaleString(getUILocale())}</Typography></TableCell></TableRow>)}</TableBody></Table></Box>}</>}<Button size="small" sx={{ alignSelf: 'flex-start' }} onClick={() => router.push(`/behavior?asset=${encodeURIComponent(asset)}`)}>{i18nText("ui:m_a35d4645ba9271d011ee")}</Button></Stack></AccordionDetails></Accordion>;
}
