// API client for Netcap Web UI backend

const API_BASE = typeof window !== 'undefined' ? '/api' : 'http://localhost:8080/api';

export interface ProcessingStats {
  currentFile: string;
  fileIndex: number;
  totalFiles: number;
  packetsProcessed: number;
  totalPackets: number;
  progressPercent: number;
  packetsPerSecond: number;
  profilesCount: number;
  servicesCount: number;
  lastUpdate: number;
}

export interface FileError {
  inputFile: string;
  error: string;
  timestamp: number;
}

export interface StatsResponse {
  processingStats: ProcessingStats;
  fileErrors: {[key: string]: FileError};
}

export interface StatusResponse {
  isProcessing: boolean;
  outputDir: string;
  inputFiles: string[];
  serverStarted: string;
  activeInputFile: string;
  isMultiFile: boolean;
}

export interface FileInfo {
  name: string;
  path: string;
  size: number;
  modifiedTime: number;
  isCompleted: boolean;
  error?: string;
}

export interface AuditFileInfo extends FileInfo {
  type: string;
  recordCount?: number;
  layer: string;
}

export interface AuditMetadata {
  type: string;
  version: string;
  inputSource: string;
  created: number;
  recordCount: number;
}

export const api = {
  async getStatus(): Promise<StatusResponse> {
    const res = await fetch(`${API_BASE}/status`);
    if (!res.ok) throw new Error('Failed to fetch status');
    return res.json();
  },

  async getStats(): Promise<StatsResponse> {
    const res = await fetch(`${API_BASE}/stats`);
    if (!res.ok) throw new Error('Failed to fetch stats');
    return res.json();
  },

  async getInputFiles(): Promise<FileInfo[]> {
    const res = await fetch(`${API_BASE}/files/input`);
    if (!res.ok) throw new Error('Failed to fetch input files');
    return res.json();
  },

  async getAuditFiles(): Promise<AuditFileInfo[]> {
    const res = await fetch(`${API_BASE}/files/audit`);
    if (!res.ok) throw new Error('Failed to fetch audit files');
    return res.json();
  },

  async getLogFiles(): Promise<FileInfo[]> {
    const res = await fetch(`${API_BASE}/files/logs`);
    if (!res.ok) throw new Error('Failed to fetch log files');
    return res.json();
  },

  async getAuditMetadata(type: string): Promise<AuditMetadata> {
    const res = await fetch(`${API_BASE}/audit/${type}/meta`);
    if (!res.ok) throw new Error('Failed to fetch audit metadata');
    return res.json();
  },

  async getLogContent(name: string): Promise<string> {
    const res = await fetch(`${API_BASE}/logs/${name}`);
    if (!res.ok) throw new Error('Failed to fetch log content');
    return res.text();
  },

  async setActiveDirectory(inputFile: string): Promise<{success: boolean; outputDir: string; activeInputFile: string}> {
    const res = await fetch(`${API_BASE}/set-directory`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ inputFile }),
    });
    if (!res.ok) throw new Error('Failed to set active directory');
    return res.json();
  },

  // Create SSE connection for streaming audit records
  streamAuditRecords(
    type: string,
    offset: number,
    limit: number,
    onRecord: (record: any) => void,
    onProgress?: (count: number) => void,
    onComplete?: (total: number) => void,
    onError?: (error: string) => void
  ): EventSource {
    const url = `${API_BASE}/audit/${type}/stream?offset=${offset}&limit=${limit}`;
    const eventSource = new EventSource(url);

    eventSource.addEventListener('record', (e) => {
      try {
        const record = JSON.parse(e.data);
        onRecord(record);
      } catch (err) {
        console.error('Failed to parse record:', err);
      }
    });

    if (onProgress) {
      eventSource.addEventListener('progress', (e) => {
        try {
          const data = JSON.parse(e.data);
          onProgress(data.count);
        } catch (err) {
          console.error('Failed to parse progress:', err);
        }
      });
    }

    if (onComplete) {
      eventSource.addEventListener('complete', (e) => {
        try {
          const data = JSON.parse(e.data);
          onComplete(data.total);
          eventSource.close();
        } catch (err) {
          console.error('Failed to parse complete:', err);
        }
      });
    }

    eventSource.addEventListener('error', (e: any) => {
      if (e.data) {
        try {
          const error = JSON.parse(e.data);
          if (onError) onError(error.error);
        } catch (err) {
          if (onError) onError('Stream error occurred');
        }
      }
      eventSource.close();
    });

    return eventSource;
  },
};

// Format bytes to human readable string
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Format timestamp to human readable string
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

