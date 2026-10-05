import { useEffect, useState } from 'react';
import type { Alert } from '../lib/api';

export function useLiveAlerts(url: string | null, restart = 0) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [state, setState] = useState<'connecting' | 'connected' | 'reconnecting' | 'gap' | 'unavailable'>('connecting');
  const [error, setError] = useState('');
  useEffect(() => {
    setAlerts([]);
    setError('');
    setState('connecting');
    if (!url || typeof EventSource === 'undefined') { setState('unavailable'); return; }
    const source = new EventSource(url);
    source.addEventListener('connected', () => setState('connected'));
    source.addEventListener('alert', event => {
      try {
        const alert = JSON.parse((event as MessageEvent).data) as Alert;
        if (!alert.alertId || typeof alert.name !== 'string') throw new Error('Invalid alert payload');
        setAlerts(previous => [alert, ...previous.filter(item => item.alertId !== alert.alertId)].slice(0, 200));
        setState('connected');
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Invalid alert event');
        setState('gap');
        source.close();
      }
    });
    source.addEventListener('gap', event => {
      try { setError(JSON.parse((event as MessageEvent).data).error ?? 'Alert history changed'); }
      catch { setError('Alert history changed'); }
      setState('gap');
      source.close();
    });
    source.onerror = () => setState('reconnecting');
    return () => source.close();
  }, [url, restart]);
  return { alerts, state, error };
}
