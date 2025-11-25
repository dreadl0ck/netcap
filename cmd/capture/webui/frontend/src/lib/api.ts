// API client for Netcap Web UI backend

// Get backend URL - defaults to localhost:8080
// In production builds, this can be overridden via NEXT_PUBLIC_BACKEND_URL
export function getBackendUrl(): string {
  // Check if running in browser
  if (typeof window !== 'undefined') {
    // Allow override via window object (for embedded scenarios)
    const windowWithBackend = window as { __BACKEND_URL__?: string };
    if (windowWithBackend.__BACKEND_URL__) {
      return windowWithBackend.__BACKEND_URL__;
    }
  }
  
  // Use environment variable if set, otherwise default to localhost:8080
  return process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080';
}

const API_BASE = `${getBackendUrl()}/api`;

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
  // Service mode specific fields
  queueLength?: number;
  jobsScheduled?: number;
  jobsProcessed?: number;
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
  isServiceMode?: boolean;  // Optional, indicates service mode
  isLiveMode: boolean;  // Whether in live capture mode
}

export interface UploadResponse {
  sessionId?: string;  // Service mode
  status?: string;     // Service mode
  message: string;
  remaining?: number;  // Service mode
  shareUrl?: string;   // Service mode
  // Local mode fields
  success?: boolean;
  filename?: string;
  path?: string;
  size?: number;
  id?: string;  // Local mode: file ID for progress tracking
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

export interface ProgressInfo {
  sessionId: string;
  status: string;
  progressPercent: number;
  message: string;
  errorMessage?: string;
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
  errorLogPath?: string;  // Path to detailed error log file
  startTime?: string;
  completionTime?: string;
  packetsTotal?: number;
  resultsReady: boolean;
  shareUrl: string;
}

export interface FileInfo {
  id: string;  // Unique identifier for the file (used for API calls)
  name: string;
  path: string;
  size: number;
  modifiedTime: number;
  isCompleted: boolean;
  error?: string;
  errorLogPath?: string;  // Path to detailed error log file
  sessionId?: string;  // Optional, only present in try service mode
  bpfFilter?: string;  // Optional, BPF filter applied during capture
  processingTime?: number;  // Optional, processing duration in seconds
  hash?: string;  // Optional, SHA256 hash of the file
  hasReportedIssue?: boolean;  // Optional, whether an issue has been reported for this file
}

export interface ExtractedFileInfo {
  name: string;
  path: string;
  fullPath: string;
  size: number;
  modifiedTime: number;
  mimeType: string;
  hash?: string;  // SHA256 hash from File audit record
}

export interface ExtractedFilesResponse {
  files: ExtractedFileInfo[];
  totalCount: number;
  filesDir: string;
}

export interface ErrorLogInfo {
  sessionId?: string;          // Service mode
  inputFile?: string;           // Local mode
  inputFilename: string;
  inputFileSize: number;
  errorCount: number;
  errorLogPath: string;
  outputDir: string;
}

export interface AggregatedError {
  errorMessage: string;
  count: number;
  firstSeen: string;
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
  moduleProtocols: Record<string, string[]>; // New: protocols supported by each module
  ndpiProtocolsUrl: string;
  libprotoidentProtocolsUrl: string;
}

export interface UserDPIPreferences {
  enabledModules: string[];
  lastUpdated: string;
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
  isServiceMode?: boolean;
  sessionId?: string;
  sessionSpecific?: boolean;
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

export interface DecoderConfigFile {
  name: string;
  path: string;
  modifiedTime: number;
  size: number;
}

export interface FieldInfo {
  name: string;
  type: string;
}

export interface DecoderFieldsResponse {
  decoderName: string;
  fields: FieldInfo[];
}

export interface AllDecoderFieldsResponse {
  [decoderName: string]: FieldInfo[];
}

export interface HarvesterInfo {
  name: string;
  description: string;
  ports: number[];
}

export interface HarvestersResponse {
  harvesters: HarvesterInfo[];
}

export interface HarvesterConfigItem {
  name: string;
  description?: string;
  enabled: boolean;
  ports: number[];
  parameters?: { [key: string]: any };
}

export interface CustomHarvesterConfig {
  name: string;
  description?: string;
  enabled: boolean;
  ports: number[];
  regex: string;
  parameters?: { [key: string]: any };
}

export interface HarvestersConfig {
  harvesters: HarvesterConfigItem[];
  custom_harvesters?: CustomHarvesterConfig[];
}

export interface HarvesterPresetInfo {
  name: string;
  description: string;
  created_at: string;
  modified_at: string;
  harvester_count: number;
}

export interface HarvesterPresetListResponse {
  presets: HarvesterPresetInfo[];
}

export interface ServiceProbeInfo {
  id: string;
  protocol: string;
  probeName: string;
  service: string;
  pattern: string;
  product: string;
  version: string;
  info: string;
  hostname: string;
  os: string;
  deviceType: string;
  cpes: string[];
  ports: number[];
  sslPorts: number[];
  rarity: number;
  isSoftMatch: boolean;
  sendString: string;
  rawLine: string;
  lineNumber: number;
  probeProtocol: string;
}

export interface ServiceProbesResponse {
  probes: ServiceProbeInfo[];
  totalCount: number;
}

export interface TestProbeRequest {
  pattern: string;
  sampleInput: string;
  flags?: string;
}

export interface TestProbeResponse {
  matches: boolean;
  capturedGroups: Record<string, string>;
  error?: string;
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

export interface NetworkInterfaceInfo {
  index: number;
  name: string;
  flags: string;
  hardwareAddr: string;
  mtu: number;
  addrs: string[];
}

export interface BPFExample {
  name: string;
  filter: string;
  description: string;
}

export interface BPFInfoResponse {
  currentFilter: string;
  examples: BPFExample[];
  docsUrl: string;
}

export interface BPFConfig {
  filter: string;
}

export interface ChartDataPoint {
  timestamp: number;
  value: number;
}

export interface ChartDataResponse {
  type: string;
  field: string;
  interval: string;
  data: ChartDataPoint[];
  count: number;
  minValue: number;
  maxValue: number;
  avgValue: number;
}

export interface ChartFieldInfo {
  name: string;
  type: string;
  description: string;
}

export interface ChartFieldsResponse {
  type: string;
  fields: ChartFieldInfo[];
  totalFields: number;   // Total possible fields including empty ones
  filteredCount: number; // Number of fields filtered out due to no data
}

export interface SankeyLink {
  source: string;
  target: string;
  value: number;
}

export interface ProtocolStats {
  count: number;
  bytes: number;
  layer: string;
}

export interface ProtocolHierarchyResponse {
  links: SankeyLink[];
  nodes: string[];
  stats: Record<string, ProtocolStats>;
}

export interface ReportIssueRequest {
  sessionId: string;
  description: string;
}

export interface ReportIssueResponse {
  success: boolean;
  issueId: string;
  message: string;
  remaining: number;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  type: string;
  expression: string;
  severity: string;
  mitre: string[];
  tags: string[];
  enabled: boolean;
  threshold?: number;
  thresholdWindow?: number;
  executionTimeMs?: number;
  lastExecuted?: number;
}

export interface RulesResponse {
  rules: Rule[];
}

export interface CreateRuleRequest {
  name: string;
  description: string;
  type: string;
  expression: string;
  severity: string;
  mitre: string[];
  tags: string[];
  enabled: boolean;
  threshold?: number;
  thresholdWindow?: number;
}

export interface UpdateRuleRequest {
  name: string;
  description: string;
  type: string;
  expression: string;
  severity: string;
  mitre: string[];
  tags: string[];
  enabled: boolean;
  threshold?: number;
  thresholdWindow?: number;
}

export interface RuleSet {
  name: string;
  filename: string;
  ruleCount: number;
  enabled: boolean;
  description: string;
}

export interface RuleSetsResponse {
  ruleSets: RuleSet[];
}

export interface UpdateRuleSetRequest {
  enabled: boolean;
}

export interface Alert {
  timestamp: number;
  name: string;
  description: string;
  ruleName: string;
  recordType: string;
  severity: string;
  tags: string[];
  mitre: string;
  srcIP: string;
  dstIP: string;
  matchedRecord: string;
  ruleExpression: string;
  threshold: number;
  thresholdWindow: number;
  resolved: boolean;
  resolvedAt?: number;
  alertId: string;
}

export interface AlertsResponse {
  alerts: Alert[];
  totalCount: number;
}

export interface GroupedAlert {
  ruleName: string;
  description: string;
  severity: string;
  recordType: string;
  tags: string[];
  mitre: string;
  ruleExpression: string;
  threshold: number;
  thresholdWindow: number;
  count: number;
  firstSeen: number;
  lastSeen: number;
  uniqueSrcIPs: string[];
  uniqueDstIPs: string[];
  uniqueSrcPorts: string[];
  uniqueDstPorts: string[];
  sampleAlerts: Alert[];
  resolved: boolean;
  resolvedCount: number;
  groupId: string;
}

export interface GroupedAlertsResponse {
  groups: GroupedAlert[];
  totalCount: number;
  groupCount: number;
}

export interface AlertStatsResponse {
  totalAlerts: number;
  groupCount: number;
  bySeverity: Record<string, number>;
  byRule: Record<string, number>;
  recentAlerts: Alert[];
  criticalAlerts: number;
  lastUpdate: number;
}

export interface FieldInfo {
  name: string;
  type: string;
  description?: string;
}

export interface FieldsResponse {
  recordType: string;
  fields: FieldInfo[];
  helpers: string[];
}

export interface FieldValuesResponse {
  recordType: string;
  fieldValues: Record<string, string[]>;
  sampleSize: number;
  maxPerField: number;
  recordsScanned: number;
}

export interface ConversationData {
  srcIP: string;
  srcPort: string;
  dstIP: string;
  dstPort: string;
  protocol: string;
  conversationData: string; // base64-encoded chunk
  exists: boolean;
  filePath: string;
  totalSize: number;  // Total file size in bytes
  chunkSize: number;  // Size of this chunk
  offset: number;     // Current offset
  hasMore: boolean;   // Whether there's more data
  errorMessage?: string;
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

  async getErrorLogContent(sessionId: string): Promise<string> {
    // Fetch error log content for a specific session by its session ID
    const res = await fetch(`${API_BASE}/error-log/${sessionId}`);
    if (!res.ok) throw new Error('Failed to fetch error log content');
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

  async getProgress(sessionId: string): Promise<ProgressInfo> {
    const res = await fetch(`${API_BASE}/progress/${sessionId}`);
    if (!res.ok) throw new Error('Failed to fetch progress');
    return res.json();
  },

  async getAllSessions(): Promise<TrySession[]> {
    const res = await fetch(`${API_BASE}/try/sessions`);
    if (!res.ok) throw new Error('Failed to fetch sessions');
    const data = await res.json();
    // Backend returns {sessions: [...]} so we need to extract the array
    return data.sessions || [];
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

  async getDPIPreferences(): Promise<UserDPIPreferences> {
    const res = await fetch(`${API_BASE}/dpi/preferences`);
    if (!res.ok) throw new Error('Failed to fetch DPI preferences');
    return res.json();
  },

  async setDPIPreferences(enabledModules: string[]): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/dpi/preferences`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ enabledModules }),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.message || 'Failed to save DPI preferences');
    }
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

  async getHarvesters(): Promise<HarvestersResponse> {
    const res = await fetch(`${API_BASE}/harvesters`);
    if (!res.ok) throw new Error('Failed to fetch harvesters');
    return res.json();
  },

  async getHarvestersConfig(): Promise<HarvestersConfig> {
    const res = await fetch(`${API_BASE}/harvesters/config`);
    if (!res.ok) throw new Error('Failed to fetch harvesters config');
    return res.json();
  },

  async saveHarvestersConfig(config: HarvestersConfig): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/harvesters/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!res.ok) throw new Error('Failed to save harvesters config');
    return res.json();
  },

  async getHarvesterPresets(): Promise<HarvesterPresetListResponse> {
    const res = await fetch(`${API_BASE}/harvesters/presets`);
    if (!res.ok) throw new Error('Failed to fetch harvester presets');
    return res.json();
  },

  async saveHarvesterPreset(name: string, config: HarvestersConfig): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/harvesters/presets/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, config }),
    });
    if (!res.ok) throw new Error('Failed to save harvester preset');
    return res.json();
  },

  async loadHarvesterPreset(name: string): Promise<{success: boolean; message: string; config: HarvestersConfig}> {
    const res = await fetch(`${API_BASE}/harvesters/presets/load`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error('Failed to load harvester preset');
    return res.json();
  },

  async deleteHarvesterPreset(name: string): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/harvesters/presets/delete`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error('Failed to delete harvester preset');
    return res.json();
  },

  async uploadHarvesterPreset(file: File, name?: string): Promise<{success: boolean; message: string; name: string}> {
    const formData = new FormData();
    formData.append('file', file);
    if (name) {
      formData.append('name', name);
    }

    const res = await fetch(`${API_BASE}/harvesters/presets/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) throw new Error('Failed to upload harvester preset');
    return res.json();
  },

  async downloadHarvesterPreset(name: string): Promise<Blob> {
    const res = await fetch(`${API_BASE}/harvesters/presets/download?name=${encodeURIComponent(name)}`);
    if (!res.ok) throw new Error('Failed to download harvester preset');
    return res.blob();
  },

  async getServiceProbes(params?: {
    limit?: number;
    offset?: number;
    search?: string;
    protocol?: string;
    service?: string;
    matchType?: string;
  }): Promise<ServiceProbesResponse> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());
    if (params?.search) queryParams.set('search', params.search);
    if (params?.protocol) queryParams.set('protocol', params.protocol);
    if (params?.service) queryParams.set('service', params.service);
    if (params?.matchType) queryParams.set('matchType', params.matchType);

    const res = await fetch(`${API_BASE}/service-probes?${queryParams}`);
    if (!res.ok) throw new Error('Failed to fetch service probes');
    return res.json();
  },

  async getServiceProbe(id: string): Promise<ServiceProbeInfo> {
    const res = await fetch(`${API_BASE}/service-probes/${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error('Failed to fetch service probe');
    return res.json();
  },

  async updateServiceProbe(id: string, probe: Partial<ServiceProbeInfo>): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/service-probes/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(probe),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to update service probe');
    }
    return res.json();
  },

  async testServiceProbe(request: TestProbeRequest): Promise<TestProbeResponse> {
    const res = await fetch(`${API_BASE}/service-probes/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    if (!res.ok) throw new Error('Failed to test service probe');
    return res.json();
  },

  exportServiceProbes(): string {
    return `${API_BASE}/service-probes/export`;
  },

  async importServiceProbes(file: File): Promise<{success: boolean; message: string; importedCount: number}> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/service-probes/import`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || error.message || 'Import failed');
    }

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

  async listDecoderConfigs(): Promise<DecoderConfigFile[]> {
    const res = await fetch(`${API_BASE}/decoders/config/list`);
    if (!res.ok) throw new Error('Failed to list decoder configs');
    return res.json();
  },

  async loadDecoderConfig(name: string): Promise<{success: boolean; message: string; config: DecoderConfig; warning?: string}> {
    const res = await fetch(`${API_BASE}/decoders/config/load`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error('Failed to load decoder config');
    return res.json();
  },

  async uploadDecoderConfig(file: File, name?: string, apply?: boolean): Promise<{success: boolean; message: string; name: string; applied: boolean}> {
    const formData = new FormData();
    formData.append('file', file);
    if (name) formData.append('name', name);
    if (apply) formData.append('apply', 'true');

    const res = await fetch(`${API_BASE}/decoders/config/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || error.message || 'Upload failed');
    }

    return res.json();
  },

  async deleteDecoderConfig(name: string): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/decoders/config/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error('Failed to delete decoder config');
    return res.json();
  },

  async saveDecoderConfigAs(name: string, config: DecoderConfig): Promise<{success: boolean; message: string; name: string}> {
    const res = await fetch(`${API_BASE}/decoders/config/save-as`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, config }),
    });
    if (!res.ok) throw new Error('Failed to save decoder config as');
    return res.json();
  },

  async getDecoderFields(decoderName: string): Promise<DecoderFieldsResponse> {
    const res = await fetch(`${API_BASE}/decoders/${encodeURIComponent(decoderName)}/fields`);
    if (!res.ok) throw new Error('Failed to fetch decoder fields');
    return res.json();
  },

  async getAllDecoderFields(): Promise<AllDecoderFieldsResponse> {
    const res = await fetch(`${API_BASE}/decoders/fields`);
    if (!res.ok) throw new Error('Failed to fetch all decoder fields');
    return res.json();
  },

  async getSystemInfo(): Promise<SystemInfo> {
    const res = await fetch(`${API_BASE}/system-info`);
    if (!res.ok) throw new Error('Failed to fetch system info');
    return res.json();
  },

  async getBPFInfo(): Promise<BPFInfoResponse> {
    const res = await fetch(`${API_BASE}/config/bpf`);
    if (!res.ok) throw new Error('Failed to fetch BPF info');
    return res.json();
  },

  async saveBPFConfig(config: BPFConfig): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/config/bpf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    if (!res.ok) throw new Error('Failed to save BPF configuration');
    return res.json();
  },

  // Create SSE connection for streaming audit records
  streamAuditRecords(
    type: string,
    offset: number,
    limit: number,
    onRecord: (record: Record<string, unknown>) => void,
    onProgress?: (count: number, scanned?: number) => void,
    onComplete?: (total: number, scanned?: number, executionTimeMs?: number) => void,
    onError?: (error: string) => void,
    filter?: string
  ): EventSource {
    let url = `${API_BASE}/audit/${type}/stream?offset=${offset}&limit=${limit}`;
    if (filter) {
      url += `&filter=${encodeURIComponent(filter)}`;
    }
    
    console.log('[API] Creating EventSource for:', url);
    const eventSource = new EventSource(url);
    
    let hasReceivedData = false;
    let timeoutId: NodeJS.Timeout | null = null;
    
    // Set a timeout to detect stalled connections (30 seconds)
    const resetTimeout = () => {
      if (timeoutId) clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        console.error('[API] Stream timeout - no data received for 30 seconds');
        if (!hasReceivedData && onError) {
          onError('Connection timeout - no response from server');
        }
        eventSource.close();
      }, 30000);
    };
    
    resetTimeout();

    eventSource.addEventListener('open', () => {
      console.log('[API] EventSource connection opened');
      hasReceivedData = true; // Consider connection open as "data received" to prevent premature timeout
      resetTimeout();
    });

    eventSource.addEventListener('record', (e) => {
      hasReceivedData = true;
      resetTimeout();
      try {
        const record = JSON.parse(e.data);
        onRecord(record);
      } catch (err) {
        console.error('Failed to parse record:', err);
      }
    });

    if (onProgress) {
      eventSource.addEventListener('progress', (e) => {
        hasReceivedData = true;
        resetTimeout();
        try {
          const data = JSON.parse(e.data);
          onProgress(data.count, data.scanned);
        } catch (err) {
          console.error('Failed to parse progress:', err);
        }
      });
    }

    if (onComplete) {
      eventSource.addEventListener('complete', (e) => {
        hasReceivedData = true;
        if (timeoutId) clearTimeout(timeoutId);
        try {
          const data = JSON.parse(e.data);
          onComplete(data.total, data.scanned, data.executionTimeMs);
          eventSource.close();
        } catch (err) {
          console.error('Failed to parse complete:', err);
        }
      });
    }

    // Handle custom error events sent from server (with data)
    eventSource.addEventListener('error', (e: Event) => {
      const messageEvent = e as MessageEvent;
      
      // Only handle if this is a custom error event with data from the server
      if (messageEvent.data) {
        if (timeoutId) clearTimeout(timeoutId);
        try {
          const error = JSON.parse(messageEvent.data);
          console.error('[API] Custom error from server:', error);
          if (onError) onError(error.error);
          eventSource.close();
        } catch (err) {
          console.error('[API] Failed to parse error data:', err);
          if (onError) onError('Stream error occurred');
          eventSource.close();
        }
      }
    });
    
    // Handle standard EventSource connection errors (built-in onerror)
    eventSource.onerror = (e) => {
      if (timeoutId) clearTimeout(timeoutId);
      console.error('[API] EventSource onerror fired, readyState:', eventSource.readyState);
      
      // Only report error if we haven't received any data yet or if truly closed
      if (!hasReceivedData) {
        if (onError) {
          onError('Failed to connect to audit record stream. The file may not exist or be incomplete.');
        }
        eventSource.close();
      } else if (eventSource.readyState === EventSource.CLOSED) {
        console.log('[API] EventSource closed after receiving data (this is normal on completion)');
        // Don't report error if we successfully received data and then closed
      }
    };

    return eventSource;
  },

  async getNetworkInterfaces(): Promise<NetworkInterfaceInfo[]> {
    const res = await fetch(`${API_BASE}/network-interfaces`);
    if (!res.ok) throw new Error('Failed to fetch network interfaces');
    return res.json();
  },

  async stopCapture(): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/stop-capture`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to stop capture');
    return res.json();
  },

  async getChartData(type: string, field: string, interval: string): Promise<ChartDataResponse> {
    const res = await fetch(`${API_BASE}/chart/data?type=${encodeURIComponent(type)}&field=${encodeURIComponent(field)}&interval=${encodeURIComponent(interval)}`);
    if (!res.ok) throw new Error('Failed to fetch chart data');
    return res.json();
  },

  async getChartFields(type: string): Promise<ChartFieldsResponse> {
    const res = await fetch(`${API_BASE}/chart/fields?type=${encodeURIComponent(type)}`);
    if (!res.ok) {
      if (res.status === 404) {
        throw new Error('Chart API not found');
      }
      if (res.status === 503) {
        throw new Error('No output directory selected - please select or set an output directory first');
      }
      const text = await res.text();
      throw new Error(text || 'Failed to fetch chart fields');
    }
    return res.json();
  },

  async getProtocolHierarchy(): Promise<ProtocolHierarchyResponse> {
    const res = await fetch(`${API_BASE}/visualize/protocol-hierarchy`);
    if (!res.ok) {
      if (res.status === 503) {
        throw new Error('No output directory selected - please select or set an output directory first');
      }
      const text = await res.text();
      throw new Error(text || 'Failed to fetch protocol hierarchy');
    }
    return res.json();
  },

  async reportIssue(sessionId: string, description: string): Promise<ReportIssueResponse> {
    const res = await fetch(`${API_BASE}/report-issue`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sessionId, description }),
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || error.message || 'Failed to report issue');
    }

    return res.json();
  },

  // Rules API
  async getRules(): Promise<RulesResponse> {
    const res = await fetch(`${API_BASE}/rules`);
    if (!res.ok) throw new Error('Failed to fetch rules');
    return res.json();
  },

  async getRule(id: string): Promise<Rule> {
    const res = await fetch(`${API_BASE}/rules/${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error('Failed to fetch rule');
    return res.json();
  },

  async createRule(rule: CreateRuleRequest): Promise<{success: boolean; message: string; rule: Rule}> {
    const res = await fetch(`${API_BASE}/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to create rule');
    }
    return res.json();
  },

  async updateRule(id: string, rule: UpdateRuleRequest): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/rules/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to update rule');
    }
    return res.json();
  },

  async deleteRule(id: string): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/rules/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to delete rule');
    }
    return res.json();
  },

  async executeRule(ruleId: string): Promise<{success: boolean; message: string; alertsCount: number; recordsRead: number; executionTimeMs: number}> {
    const res = await fetch(`${API_BASE}/rules/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ruleId }),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to execute rule');
    }
    return res.json();
  },

  async executeAllRules(): Promise<{
    success: boolean; 
    message: string; 
    totalAlerts: number; 
    totalRecords: number; 
    executionTimeMs: number;
    ruleResults: Array<{
      ruleName: string;
      alertsCount: number;
      recordsRead: number;
      success: boolean;
      error?: string;
      executionTimeMs: number;
    }>;
  }> {
    const res = await fetch(`${API_BASE}/rules/execute-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to execute all rules');
    }
    return res.json();
  },

  // Rule Sets API
  async getRuleSets(): Promise<RuleSetsResponse> {
    const res = await fetch(`${API_BASE}/rule-sets`);
    if (!res.ok) throw new Error('Failed to fetch rule sets');
    return res.json();
  },

  async updateRuleSet(name: string, request: UpdateRuleSetRequest): Promise<{success: boolean; message: string; rulesAffected: number}> {
    const res = await fetch(`${API_BASE}/rule-sets/${encodeURIComponent(name)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Failed to update rule set');
    }
    return res.json();
  },

  // Alerts API
  async getAlerts(params?: {
    limit?: number;
    offset?: number;
    severity?: string;
    ruleName?: string;
    sort?: 'asc' | 'desc';
  }): Promise<AlertsResponse> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());
    if (params?.severity) queryParams.set('severity', params.severity);
    if (params?.ruleName) queryParams.set('ruleName', params.ruleName);
    if (params?.sort) queryParams.set('sort', params.sort);

    const res = await fetch(`${API_BASE}/alerts?${queryParams}`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  async getGroupedAlerts(params?: {
    limit?: number;
    offset?: number;
    severity?: string;
    ruleName?: string;
    sort?: 'asc' | 'desc';
    sortBy?: 'count' | 'lastSeen' | 'firstSeen' | 'severity';
  }): Promise<GroupedAlertsResponse> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.set('limit', params.limit.toString());
    if (params?.offset) queryParams.set('offset', params.offset.toString());
    if (params?.severity) queryParams.set('severity', params.severity);
    if (params?.ruleName) queryParams.set('ruleName', params.ruleName);
    if (params?.sort) queryParams.set('sort', params.sort);
    if (params?.sortBy) queryParams.set('sortBy', params.sortBy);

    const res = await fetch(`${API_BASE}/alerts/grouped?${queryParams}`);
    if (!res.ok) throw new Error('Failed to fetch grouped alerts');
    return res.json();
  },

  async getAlertStats(): Promise<AlertStatsResponse> {
    const res = await fetch(`${API_BASE}/alerts/stats`);
    if (!res.ok) throw new Error('Failed to fetch alert statistics');
    return res.json();
  },

  async clearAlerts(): Promise<{success: boolean; message: string}> {
    const res = await fetch(`${API_BASE}/alerts/clear`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to clear alerts');
    return res.json();
  },

  async resolveAlert(alertId?: string, groupId?: string): Promise<{success: boolean; message: string; resolvedAt: number; resolvedIds?: string[]}> {
    const res = await fetch(`${API_BASE}/alerts/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ alertId, groupId }),
    });
    if (!res.ok) throw new Error('Failed to resolve alert');
    return res.json();
  },

  async unresolveAlert(alertId?: string, groupId?: string): Promise<{success: boolean; message: string; unresolvedIds?: string[]}> {
    const res = await fetch(`${API_BASE}/alerts/unresolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ alertId, groupId }),
    });
    if (!res.ok) throw new Error('Failed to unresolve alert');
    return res.json();
  },

  // Files API
  async getExtractedFiles(): Promise<ExtractedFilesResponse> {
    const res = await fetch(`${API_BASE}/extracted-files`);
    if (!res.ok) throw new Error('Failed to fetch extracted files');
    return res.json();
  },

  downloadExtractedFile(relativePath: string): string {
    // Return the download URL for the file
    return `${API_BASE}/extracted-files/download/${encodeURIComponent(relativePath)}`;
  },

  downloadAllExtractedFiles(): string {
    // Return the download URL for all extracted files as a zip
    return `${API_BASE}/extracted-files/download-all`;
  },

  downloadInputFile(identifier: string): string {
    // Return the download URL for the input PCAP file
    // identifier is sessionId in service mode or file path in local mode
    return `${API_BASE}/files/input/download/${encodeURIComponent(identifier)}`;
  },

  // Get field information for autocomplete
  async getAuditRecordFields(type: string): Promise<FieldsResponse> {
    const res = await fetch(`${API_BASE}/audit/${encodeURIComponent(type)}/fields`);
    if (!res.ok) throw new Error('Failed to fetch field information');
    return res.json();
  },

  // Get sample field values for autocomplete
  async getAuditRecordFieldValues(type: string): Promise<FieldValuesResponse> {
    const res = await fetch(`${API_BASE}/audit/${encodeURIComponent(type)}/values`);
    if (!res.ok) throw new Error('Failed to fetch field values');
    return res.json();
  },

  // Error Logs API
  async getErrorLogs(): Promise<ErrorLogInfo[]> {
    const res = await fetch(`${API_BASE}/error-logs`);
    if (!res.ok) throw new Error('Failed to fetch error logs');
    return res.json();
  },

  async getAggregatedErrors(): Promise<AggregatedError[]> {
    const res = await fetch(`${API_BASE}/error-logs/aggregated`);
    if (!res.ok) throw new Error('Failed to fetch aggregated errors');
    return res.json();
  },

  // Conversation Data API
  async getConnectionConversation(
    srcIP: string,
    srcPort: string,
    dstIP: string,
    dstPort: string,
    protocol: string,
    offset?: number,
    limit?: number
  ): Promise<ConversationData> {
    const params = new URLSearchParams({
      srcIP,
      srcPort,
      dstIP,
      dstPort,
      protocol,
    });
    if (offset !== undefined) {
      params.set('offset', offset.toString());
    }
    if (limit !== undefined) {
      params.set('limit', limit.toString());
    }
    const res = await fetch(`${API_BASE}/connections/conversation?${params}`);
    if (!res.ok) throw new Error('Failed to fetch conversation data');
    return res.json();
  },

  // Count APIs for menu badges
  async getHostsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/hosts`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getDevicesCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/devices`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getConnectionsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/connections`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getCertificatesCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/certificates`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getHTTPCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/http`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getCredentialsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/credentials`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getDomainsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/domains`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getFingerprintsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/fingerprints`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getSoftwareCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/software`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getVulnerabilitiesCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/vulnerabilities`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalVulns || 0;
  },

  async getAuditRecordsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/files/audit`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.length || 0;
  },

  async getServicesCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/services`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.totalCount || 0;
  },

  async getLogsCount(): Promise<number> {
    const res = await fetch(`${API_BASE}/files/logs`);
    if (!res.ok) return 0;
    const data = await res.json();
    return data.length || 0;
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
  // Handle invalid timestamps
  if (!timestamp || timestamp === 0 || Number.isNaN(timestamp)) {
    return 'N/A';
  }
  
  // Detect timestamp format based on magnitude
  // Timestamps > 10^15 are likely nanoseconds (e.g., 1700000000000000000)
  // Timestamps < 10^12 are likely seconds (e.g., 1700000000)
  // Timestamps between 10^12 and 10^15 are likely milliseconds
  let dateMs: number;
  
  if (timestamp > 1e15) {
    // Nanoseconds - divide by 1,000,000 to get milliseconds
    dateMs = timestamp / 1e6;
  } else if (timestamp > 1e12) {
    // Already in milliseconds
    dateMs = timestamp;
  } else {
    // Seconds - multiply by 1000 to get milliseconds
    dateMs = timestamp * 1000;
  }
  
  const date = new Date(dateMs);
  
  // Check if the date is valid
  if (Number.isNaN(date.getTime())) {
    return 'Invalid Date';
  }
  
  // Additional validation: check if date is reasonable (between 1970 and 2100)
  const year = date.getFullYear();
  if (year < 1970 || year > 2100) {
    return 'Invalid Date';
  }
  
  return date.toLocaleString();
}

export function formatDuration(seconds: number): string {
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)}ms`;
  }
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.floor(seconds % 60);
  if (minutes < 60) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
}

