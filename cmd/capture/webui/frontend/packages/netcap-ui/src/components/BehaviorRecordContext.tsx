import { Alert, Stack, Typography } from '@mui/material';

import { useNetcapConfig } from '../providers';
import { behaviorRequest } from '../lib/behavior';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, formatNumber as i18nNumber, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { renderError } from "../lib/i18n";




interface RecordContext {
  records: { type: string; index: number; sha256: string; firstSeen: number; lastSeen: number;
    captureLagNS: number; outcome: string; authentication: string; status?: number; command?: number; encrypted?: boolean }[];
  unavailable: string[];
  scanned: number;
  truncated: boolean;
  qualification: string;
}

export default function BehaviorRecordContext({ alertId, selection }: { alertId: string; selection: string }) {
  const __uiLocale = useUILocale();
  const config = useNetcapConfig();
  const url = `${config.apiBaseUrl}/behavior/records${selection || '?'}${selection ? '&' : ''}alertId=${encodeURIComponent(alertId)}`;
  const { data, error } = useSWR<RecordContext>(url, () => behaviorRequest(config.fetch ?? fetch, url),
    { refreshInterval: 5000, keepPreviousData: false });
  return <Stack spacing={1} role="region" aria-label={i18nText("ui:m_90529f772b23a1c2beb1")}><Typography variant="subtitle2">{i18nText("ui:m_90529f772b23a1c2beb1")}</Typography>{error && <Alert severity="warning">{renderError(error)}</Alert>}{!data && !error && <Typography variant="body2">{i18nText("ui:m_9dee9e010cd9c0e27c8e")}</Typography>}{data && <><Alert severity="info">{data.qualification}</Alert><Typography variant="caption">{i18nRichText("ui:m_66cb2d5183ff8df7e67b", { arg0: data.records.length, arg1: data.scanned, arg2: data.truncated ? i18nText("ui:m_1f65c9a3b816ca6d22aa") : '' })}</Typography>{data.unavailable.map(message => <Typography key={message} variant="body2" color="text.secondary">{message}</Typography>)}{!data.records.length && <Typography variant="body2">{i18nText("ui:m_701878ed15f892eb8068")}</Typography>}{data.records.map(record => <Stack key={`${record.type}:${record.index}:${record.sha256}`} spacing={0.25}><Typography variant="body2">{i18nRichText("ui:m_a44613bb812c64d6e368", { arg0: record.type, arg1: record.index, arg2: record.outcome, arg3: record.authentication })}</Typography><Typography variant="caption">{i18nRichText("ui:m_5ab1262cde26f12f8f1c", { arg0: new Date(record.firstSeen / 1e6).toLocaleString(getUILocale()), arg1: new Date(record.lastSeen / 1e6).toLocaleString(getUILocale()), arg2: i18nNumber((record.captureLagNS / 1e9), { minimumFractionDigits: 3, maximumFractionDigits: 3, useGrouping: false }) })}</Typography>{record.type === 'SMB' && <Typography variant="caption">{i18nRichText("ui:m_23b6ffa23a4a1421a555", { arg0: record.command ?? 0, arg1: record.status ?? 0, arg2: record.encrypted ? i18nText("ui:m_60e76b59b42f5b8992e2") : '' })}</Typography>}<Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>{i18nRichText("ui:m_9993a7af532376fd3ca1", { arg0: record.sha256 })}</Typography></Stack>)}</>}</Stack>;
}
