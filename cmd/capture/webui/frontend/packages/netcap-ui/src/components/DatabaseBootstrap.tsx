/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  LinearProgress,
  Snackbar,
  Typography,
} from '@mui/material';
import {
  Storage as StorageIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { useNetcapApi } from '../hooks';
import type { DatabaseDownloadStatus, DatabaseStatus } from '../lib/api';

/** Poll interval while a download is running. */
const PROGRESS_POLL_MS = 1000;

/** Key recording that the user dismissed the prompt for this app run. */
const DISMISS_KEY = 'netcap.dbBootstrap.dismissed';

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function describeDownload(download: DatabaseDownloadStatus): string {
  if (download.message) return download.message;
  switch (download.stage) {
    case 'metadata':
      return 'Checking for the latest database version';
    case 'download':
      return download.total > 0
        ? `Downloading ${formatBytes(download.downloaded)} of ${formatBytes(download.total)}`
        : `Downloading ${formatBytes(download.downloaded)}`;
    case 'extract':
      return 'Extracting databases';
    default:
      return 'Working';
  }
}

export interface DatabaseBootstrapProps {
  /** Milliseconds to wait after mount before the first check. */
  startupDelayMs?: number;
}

/**
 * Prompts for the one-time database download and shows its progress.
 *
 * This exists because nothing shipped the GeoLite2 databases on any platform
 * and nothing fetched them: `-geoDB` defaults on, the resolver aborted the
 * process when the file was absent, and every capture on a clean install
 * failed before the first packet with no message a user could read.
 *
 * The download is never started automatically. It is ~91 MB over someone
 * else's connection, so it is offered and the user presses the button; that
 * is also what makes the progress bar meaningful rather than a surprise.
 */
export default function DatabaseBootstrap({ startupDelayMs = 1500 }: DatabaseBootstrapProps) {
  const api = useNetcapApi();

  const [status, setStatus] = useState<DatabaseStatus | null>(null);
  const [download, setDownload] = useState<DatabaseDownloadStatus | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  // Guards the download-finished refresh so a completed run cannot re-arm the
  // prompt on every poll.
  const refreshedAfterFinish = useRef(false);

  useEffect(() => {
    try {
      setDismissed(sessionStorage.getItem(DISMISS_KEY) === '1');
    } catch {
      // Private browsing or a sandboxed webview: treat as not dismissed.
    }
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      const next = await api.getDatabaseStatus();
      setStatus(next);
      if (next) setDownload(next.download);
    } catch (err) {
      // A backend without this endpoint, or one still starting, is not an
      // error worth interrupting anyone over. The prompt simply stays hidden.
      console.debug('[DBs] status unavailable:', err);
      setStatus(null);
    }
  }, [api]);

  useEffect(() => {
    const timer = setTimeout(refreshStatus, startupDelayMs);
    return () => clearTimeout(timer);
  }, [refreshStatus, startupDelayMs]);

  const running = download?.state === 'running';

  useEffect(() => {
    if (!running) return undefined;

    let cancelled = false;
    const interval = setInterval(async () => {
      try {
        const next = await api.getDatabaseDownloadProgress();
        if (cancelled || !next) return;
        setDownload(next);
      } catch (err) {
        console.debug('[DBs] progress unavailable:', err);
      }
    }, PROGRESS_POLL_MS);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [api, running]);

  // Re-read status once the download settles, so a success actually clears the
  // prompt instead of leaving it claiming the databases are still missing.
  useEffect(() => {
    if (download?.state !== 'completed') {
      refreshedAfterFinish.current = false;
      return;
    }
    if (refreshedAfterFinish.current) return;
    refreshedAfterFinish.current = true;
    refreshStatus();
  }, [download?.state, refreshStatus]);

  const handleDownload = useCallback(async () => {
    setStartError(null);
    // Show the running state immediately. The poll is a second away and an
    // unresponsive button is the thing people click twice.
    setDownload({ state: 'running', stage: 'metadata', downloaded: 0, total: 0, percent: 0 });

    try {
      const result = await api.updateDatabases();
      if (result.download) setDownload(result.download);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setStartError(message);
      setDownload({
        state: 'failed',
        downloaded: 0,
        total: 0,
        percent: 0,
        error: message,
      });
    }
  }, [api]);

  const handleDismiss = useCallback(() => {
    setDismissed(true);
    try {
      sessionStorage.setItem(DISMISS_KEY, '1');
    } catch {
      // Not persisting a dismissal is harmless; it reappears next launch.
    }
  }, []);

  // Nothing to say: no backend support, or every required database present and
  // no download in flight.
  if (!status) return null;
  const failed = download?.state === 'failed';
  const completed = download?.state === 'completed';

  if (status.satisfied && !running && !failed) return null;
  if (dismissed && !running && !failed) return null;

  const open = true;
  const severity = failed ? 'error' : running ? 'info' : completed ? 'success' : 'warning';

  return (
    <Snackbar
      open={open}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      sx={{ maxWidth: 520 }}
    >
      <Alert
        severity={severity}
        icon={running ? <DownloadIcon /> : <StorageIcon />}
        variant="filled"
        sx={{ width: '100%' }}
        onClose={running ? undefined : handleDismiss}
      >
        <AlertTitle>
          {failed
            ? 'Database download failed'
            : running
              ? 'Downloading analysis databases'
              : 'Analysis databases are missing'}
        </AlertTitle>

        {!running && !failed && (
          <Typography variant="body2" sx={{ mb: 1 }}>
            Captures will still be analysed, but{' '}
            {Array.from(new Set(status.missing.map(m => m.feature))).join(', ') || 'some enrichment'}{' '}
            is disabled until the databases are installed. This is a one-time download of about 90 MB.
          </Typography>
        )}

        {failed && (
          <Typography variant="body2" sx={{ mb: 1, wordBreak: 'break-word' }}>
            {startError || download?.error || 'The download did not complete.'}
          </Typography>
        )}

        {running && download && (
          <Box sx={{ mb: 1 }}>
            <LinearProgress
              variant={download.stage === 'download' && download.total > 0 ? 'determinate' : 'indeterminate'}
              value={download.percent}
              sx={{ height: 6, borderRadius: 1, mb: 0.5 }}
            />
            <Typography variant="caption">{describeDownload(download)}</Typography>
          </Box>
        )}

        {!running && (
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              color="inherit"
              startIcon={<DownloadIcon />}
              onClick={handleDownload}
            >
              {failed ? 'Try again' : 'Download databases'}
            </Button>
            <Button size="small" color="inherit" onClick={handleDismiss}>
              Not now
            </Button>
          </Box>
        )}
      </Alert>
    </Snackbar>
  );
}
