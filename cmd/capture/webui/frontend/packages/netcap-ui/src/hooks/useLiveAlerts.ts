import { useEffect, useState } from 'react';
import type { Alert } from '../lib/api';
import { message as i18nMessage, type MessageText as UIMessageText } from "../lib/i18n";
import { message, displayError } from "../lib/i18n";
import { errorText, metadataMessage, localeURL } from "../lib/i18n";




export function useLiveAlerts(url: string | null, restart = 0) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [state, setState] = useState<'connecting' | 'connected' | 'reconnecting' | 'gap' | 'unavailable'>('connecting');
  const [error, setError] = useState<UIMessageText>('');
  useEffect(() => {
    setAlerts([]);
    setError('');
    setState('connecting');
    if (!url || typeof EventSource === 'undefined') { setState('unavailable'); return; }
    const source = new EventSource(localeURL(url));
    source.addEventListener('connected', () => setState('connected'));
    source.addEventListener('alert', event => {
      try {
        const alert = JSON.parse((event as MessageEvent).data) as Alert;
        if (!alert.alertId || typeof alert.name !== 'string') throw displayError(message("ui:m_0d98d61b61c699063396"));
        setAlerts(previous => [alert, ...previous.filter(item => item.alertId !== alert.alertId)].slice(0, 200));
        setState('connected');
      } catch (error) {
        setError(error instanceof Error ? errorText(error) : i18nMessage("ui:m_38a4e73c6b0da3a5d63c"));
        setState('gap');
        source.close();
      }
    });
    source.addEventListener('gap', event => {
      try { setError(metadataMessage(JSON.parse((event as MessageEvent).data), 'error') || i18nMessage("ui:m_c963bce9f69fc31eb8d7")); }
      catch { setError(i18nMessage("ui:m_c963bce9f69fc31eb8d7")); }
      setState('gap');
      source.close();
    });
    source.onerror = () => setState('reconnecting');
    return () => source.close();
  }, [url, restart]);
  return { alerts, state, error };
}
