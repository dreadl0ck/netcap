import { useState } from 'react';
import { Alert, Box, Button } from '@mui/material';
import { useNetcapConfig } from '../providers';
import type { OfflineSelection } from '../lib/api';
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { message, displayError } from "../lib/i18n";
import { errorText } from "../lib/i18n";




export default function ReproductionDownload({ selection, reviewedLog = false }: { selection: OfflineSelection & { runId?: string }; reviewedLog?: boolean }) {
  const __uiLocale = useUILocale();
  const config = useNetcapConfig();
  const [error, setError] = useState<UIMessageText>('');
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true); setError('');
    try {
      if (!selection.sessionId && !selection.inputFile) throw displayError(message("ui:m_dde1772f644bb962cb92"));
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(selection)) if (value) query.set(key, value);
      if (reviewedLog) query.set('reviewedLog', 'true');
      const response = await (config.fetch || fetch)(`${config.apiBaseUrl}/investigation/reproduction?${query}`);
      if (!response.ok) throw displayError(message("ui:m_738048f12401f6d1efcb", { arg0: response.status }));
      const bundle = await response.json();
      if (bundle.schema !== 'netcap-reproduction-metadata/v1' || bundle.state !== 'metadata-only') throw displayError(message("ui:m_3a872b51ec997a7f4d47"));
      if (config.saveJSON) { await config.saveJSON('netcap-reproduction-metadata.json', bundle); return; }
      const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
      try {
        const link = document.createElement('a');
        link.href = url; link.download = 'netcap-reproduction-metadata.json'; link.click();
      } finally { URL.revokeObjectURL(url); }
    } catch (error) { setError(error instanceof Error ? errorText(error) : i18nMessage("ui:m_d49827d9cd53280a3443")); }
    finally { setBusy(false); }
  };
  return <Box onClick={event => event.stopPropagation()}><Button size="small" disabled={busy} onClick={download}>{reviewedLog ? i18nText("ui:m_6939312babe22ab8a8db") : i18nText("ui:m_1c655deabc24e2ffb453")}</Button>{i18nRenderText(error) && <Alert severity="error">{i18nRenderText(error)}</Alert>}</Box>;
}
