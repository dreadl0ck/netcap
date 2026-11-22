import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Dialog, DialogContent, DialogTitle } from '@mui/material';
import { useNetcapConfig } from '../providers';
import { resolveOccurrence, type AnalystSource, type OccurrenceReference } from '../lib/analyst';
import { message as i18nMessage, translate as i18nText, renderText as i18nRenderText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { errorText } from "../lib/i18n";



export default function OccurrenceAction({ data }: { data: Record<string, unknown> }) {
  const __uiLocale = useUILocale();
  const config = useNetcapConfig();
  const [error, setError] = useState<UIMessageText>(''), [record, setRecord] = useState<unknown>(null);
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  const reference = data._netcapOccurrence as OccurrenceReference | undefined;
  const source = data._netcapSource as AnalystSource | undefined;
  if (!reference || !source) return null;
  return <Box onClick={event => event.stopPropagation()}><Button onClick={async () => { operation.current?.abort(); const controller = new AbortController(); operation.current = controller; setError(''); try { const result = await resolveOccurrence(config.fetch ?? fetch, config.apiBaseUrl, source, reference, controller.signal); if (!controller.signal.aborted) setRecord(result); } catch (failure) { if (!controller.signal.aborted) setError(failure instanceof Error ? errorText(failure) : i18nMessage("ui:m_191af5f32db4b011ef7f")); } }}>{i18nText("ui:m_59902d9e4f7ae2721d88")}</Button>{i18nRenderText(error) && <Alert severity="error">{i18nRenderText(error)}</Alert>}<Dialog open={record !== null} onClose={() => setRecord(null)} fullWidth maxWidth="lg"><DialogTitle>{i18nText("ui:m_69f29391df165162ac71")}</DialogTitle><DialogContent><Button onClick={() => setRecord(null)}>{i18nText("ui:m_411211095604acea5545")}</Button><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(record, null, 2).slice(0, 40000)}</pre></DialogContent></Dialog></Box>;
}
