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

export interface AuditStatsResponse {
  totalRecords: number;
  exploitCount: number;
  vulnerabilityCount: number;
  credentialsCount: number;
  softwareCount: number;
}

export interface StatusResponse {
  isProcessing: boolean;
  outputDir: string;
  inputFiles: string[];
  serverStarted: string;
  activeInputFile: string;
  isMultiFile: boolean;
  sessionId?: string;  // Optional, only present in try service mode
  isTryService?: boolean;  // Optional, indicates try service mode
}

export interface UploadResponse {
  sessionId: string;
  status: string;
  message: string;
  remaining: number;
  shareUrl: string;
}

export interface QuotaResponse {
  limit: number;
  remaining: number;
  allowed: boolean;
  storage: {
    current: number;
    max: number;
    available: number;
    percentUsed: number;
    unlimited: boolean;
  };
}

export interface SessionStatus {
  sessionId: string;
  status: string;
  inputFilename: string;
  errorMessage?: string;
  startTime?: string;
}

export interface TrySession {
  sessionId: string;
  ip: string;
  uploadTimestamp: string;
  inputFile: string;
  inputFilename: string;
  inputFileSize: number;
  outputDir: string;
  status: string;
  errorMessage?: string;
  startTime?: string;
  completionTime?: string;
  packetsTotal?: number;
  resultsReady: boolean;
  shareUrl: string;
}

export interface FileInfo {
  name: string;
  path: string;
  size: number;
  modifiedTime: number;
  isCompleted: boolean;
  error?: string;
  sessionId?: string;  // Optional, only present in try service mode
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

export interface DBFileInfo {
  name: string;
  path: string;
  size: number;
  type: string;
  modifiedTime: number;
}

export interface DatabaseInfo {
  version: string;
  dbPath: string;
  configRootPath: string;
  files: DBFileInfo[];
  totalSize: number;
  fileCount: number;
}

export interface VersionInfo {
  version: string;
  commit: string;
  gopacketVersion: string;
}

export interface DPIInfo {
  enabled: boolean;
  hasSupport: boolean;
  ndpiVersion: string;
  libprotoidentVersion: string;
  goDpiVersion: string;
  activeModules: string[];
  availableModules: string[];
  ndpiProtocolsUrl: string;
  libprotoidentProtocolsUrl: string;
}

export interface ConfigOption {
  name: string;
  value: unknown;
  default: unknown;
  type: string;
  description: string;
  category: string;
  isEditable: boolean;
}

export interface ConfigResponse {
  readOnly: boolean;
  isTryService?: boolean;
  options: ConfigOption[];
}

export interface DecoderInfo {
  name: string;
  description: string;
  type: string;
  layer?: string;
  port?: number;
  enabled: boolean;
}

export interface DecodersResponse {
  packet: DecoderInfo[];
  gopacket: DecoderInfo[];
  stream: DecoderInfo[];
  abstract: DecoderInfo[];
}

export interface DecoderConfig {
  includeDecoders: string;
  excludeDecoders: string;
  enabledDecoders: string[];
}

export interface SystemInfo {
  numCPU: number;
  numGoroutine: number;
  totalMemory: number;
  freeMemory: number;
  usedMemory: number;
  goos: string;
  goarch: string;
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

  async getAuditStats(): Promise<AuditStatsResponse> {
    const res = await fetch(`${API_BASE}/audit-stats`);
    if (!res.ok) throw new Error('Failed to fetch audit stats');
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

  async uploadFile(file: File): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || error.message || 'Upload failed');
    }

    return res.json();
  },

  async getQuota(): Promise<QuotaResponse> {
    const res = await fetch(`${API_BASE}/quota`);
    if (!res.ok) throw new Error('Failed to fetch quota');
    return res.json();
  },

  async getSessionStatus(sessionId: string): Promise<SessionStatus> {
    const res = await fetch(`${API_BASE}/status/${sessionId}`);
    if (!res.ok) throw new Error('Failed to fetch session status');
    return res.json();
  },

  async getAllSessions(): Promise<TrySession[]> {
    const res = await fetch(`${API_BASE}/try/sessions`);
    if (!res.ok) throw new Error('Failed to fetch sessions');
    return res.json();
  },

  async selectSession(sessionId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/try/session/${sessionId}`, {
      method: 'GET',
    });
    if (!res.ok) throw new Error('Failed to select session');
  },

  async getDatabaseInfo(): Promise<DatabaseInfo> {
    const res = await fetch(`${API_BASE}/dbs`);
    if (!res.ok) throw new Error('Failed to fetch database info');
    return res.json();
  },

  async updateDatabases(): Promise<{success: boolean; message: string; error?: string}> {
    const res = await fetch(`${API_BASE}/dbs/update`, {
      method: 'POST',
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to update databases');
    }
    return res.json();
  },

  async getVersion(): Promise<VersionInfo> {
    const res = await fetch(`${API_BASE}/version`);
    if (!res.ok) throw new Error('Failed to fetch version info');
    return res.json();
  },

  async getDPIInfo(): Promise<DPIInfo> {
    const res = await fetch(`${API_BASE}/dpi`);
    if (!res.ok) throw new Error('Failed to fetch DPI info');
    return res.json();
  },

  async getConfig(): Promise<ConfigResponse> {
    const res = await fetch(`${API_BASE}/config`);
    if (!res.ok) throw new Error('Failed to fetch config');
    return res.json();
  },

  async getDebugState(): Promise<{enabled: boolean}> {
    const res = await fetch(`${API_BASE}/config/debug`);
    if (!res.ok) throw new Error('Failed to fetch debug state');
    return res.json();
  },

  async setDebugState(enabled: boolean): Promise<{enabled: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/config/debug`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) throw new Error('Failed to update debug state');
    return res.json();
  },

  async getDecoders(): Promise<DecodersResponse> {
    const res = await fetch(`${API_BASE}/decoders`);
    if (!res.ok) throw new Error('Failed to fetch decoders');
    return res.json();
  },

  async getDecoderConfig(): Promise<DecoderConfig> {
    const res = await fetch(`${API_BASE}/decoders/config`);
    if (!res.ok) throw new Error('Failed to fetch decoder config');
    return res.json();
  },

  async saveDecoderConfig(config: DecoderConfig): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/decoders/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!res.ok) throw new Error('Failed to save decoder config');
    return res.json();
  },

  async getSystemInfo(): Promise<SystemInfo> {
    const res = await fetch(`${API_BASE}/system-info`);
    if (!res.ok) throw new Error('Failed to fetch system info');
    return res.json();
  },

  // Create SSE connection for streaming audit records
  streamAuditRecords(
    type: string,
    offset: number,
    limit: number,
    onRecord: (record: Record<string, unknown>) => void,
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

    eventSource.addEventListener('error', (e: Event) => {
      const messageEvent = e as MessageEvent;
      if (messageEvent.data) {
        try {
          const error = JSON.parse(messageEvent.data);
          if (onError) onError(error.error);
        } catch {
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

