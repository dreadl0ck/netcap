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

export {
  api,
  createApi,
  getBackendUrl,
  formatBytes,
  formatTimestamp,
  formatDuration,
} from './api';

export type { NetcapApiClient } from './api';

export {
  escapeHTML,
  escapeHTMLPreservingLineBreaks,
  safeCSSColor,
  syntaxHighlightJSON,
} from './html';

export { highlightFilterExpression } from './filterSyntaxHighlight';
export type { FilterToken } from './filterSyntaxHighlight';

export { highlightBPFExpression } from './bpfSyntaxHighlight';
export type { BPFToken } from './bpfSyntaxHighlight';

export { highlightRegexPattern } from './regexSyntaxHighlight';
export type { RegexToken } from './regexSyntaxHighlight';

export {
  parseSearchQuery,
  matchesSingleValue,
  matchesSearchTerms,
  filterBySearchQuery,
} from './tableSearch';

export {
  mobileTouchTarget,
  mobileTableCell,
  mobileMonospaceFont,
  responsiveTableContainer,
  mobileTablePaginationSx,
} from './mobileMixins';

export type {
  // Response types
  ProcessingStats,
  FileError,
  StatsResponse,
  AuditStatsResponse,
  StatusResponse,
  UploadResponse,
  QuotaResponse,
  FileInfo,
  AuditFileInfo,
  AuditMetadata,
  ExtractedFileInfo,
  ExtractedFilesResponse,
  VersionInfo,
  DatabaseInfo,
  DBFileInfo,
  DPIInfo,
  UserDPIPreferences,
  ConfigOption,
  ConfigResponse,
  DecoderInfo,
  DecodersResponse,
  DecoderConfig,
  DecoderConfigFile,
  DecoderFieldsResponse,
  AllDecoderFieldsResponse,
  HarvesterInfo,
  HarvestersResponse,
  HarvestersConfig,
  HarvesterConfigItem,
  CustomHarvesterConfig,
  HarvesterPresetInfo,
  HarvesterPresetListResponse,
  ServiceProbeInfo,
  ServiceProbesResponse,
  TestProbeRequest,
  TestProbeResponse,
  NetworkInterfaceInfo,
  BPFExample,
  BPFInfoResponse,
  BPFConfig,
  SystemInfo,
  ChartDataPoint,
  ChartDataResponse,
  ChartFieldInfo,
  ChartFieldsResponse,
  ProtocolStats,
  SankeyLink,
  ProtocolHierarchyResponse,
  ReportIssueRequest,
  ReportIssueResponse,
  Rule,
  ResponseAction,
  RulesResponse,
  CreateRuleRequest,
  UpdateRuleRequest,
  RuleSet,
  RuleSetsResponse,
  UpdateRuleSetRequest,
  Alert,
  AlertsResponse,
  GroupedAlert,
  GroupedAlertsResponse,
  AlertStatsResponse,
  FieldInfo,
  FieldsResponse,
  FieldValuesResponse,
  InjectionRule,
  InjectionRulesResponse,
  CreateInjectionRuleRequest,
  UpdateInjectionRuleRequest,
  InjectionEvent,
  InjectionEventsResponse,
  InjectionStatsResponse,
  InjectionAction,
  InjectionActionConfig,
  ConversationData,
  ErrorLogInfo,
  AggregatedError,
  SessionStatus,
  ProgressInfo,
  TrySession,
} from './api';
