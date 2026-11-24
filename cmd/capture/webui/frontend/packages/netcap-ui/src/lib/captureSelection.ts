const captureEndpoints = /^\/api\/(?:status$|stats$|audit-stats$|showcase-story$|files\/(?:logs|audit|extracted)|extracted-files(?:\/|$)|audit\/|logs(?:\/|$)|menu-counts|alerts(?:\/|-|$)|chart\/|visualize\/|hosts(?:\/|-|$)|devices(?:\/|-|$)|connections(?:\/|-|$)|domains(?:\/|-|$)|services(?:\/|-|$)|software(?:\/|-|$)|http(?:\/|-|$)|fingerprints(?:\/|-|$)|certificates(?:\/|-|$)|secrets(?:\/|-|$)|vulnerabilities(?:\/|-|$)|network-detection|artifact-analysis|investigation\/|behavior(?:\/|-|$)|config$|conversation|rules\/offline\/evaluations|yara\/)/;

export function selectedSession(): string | null {
  return typeof window === 'undefined' ? null : new URLSearchParams(window.location.search).get('sessionId');
}

export function scopeCaptureURL(input: string): string {
  const id = selectedSession();
  if (!id) return input;
  const url = new URL(input, window.location.origin);
  const scope = url.searchParams.get('scope');
  if (url.origin !== window.location.origin || !captureEndpoints.test(url.pathname) ||
      url.searchParams.has('sessionId') || (scope && scope !== 'current')) return input;
  url.searchParams.set('sessionId', id);
  return url.href;
}

export function captureNavigation(path: string): string {
  const id = selectedSession();
  if (!id || !path.startsWith('/') || path.startsWith('//')) return path;
  const url = new URL(path, window.location.origin);
  if (!url.searchParams.has('sessionId')) url.searchParams.set('sessionId', id);
  return url.pathname + url.search + url.hash;
}

export function setSelectedSession(id: string) {
  if (typeof window === 'undefined' || id === selectedSession()) return;
  const url = new URL(window.location.href);
  url.searchParams.set('sessionId', id);
  url.searchParams.delete('runId');
  window.history.replaceState(window.history.state, '', url);
  window.dispatchEvent(new PopStateEvent('popstate', { state: window.history.state }));
}
