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

// Page components
// These are framework-agnostic versions of the Next.js pages
// They use useNetcapRouter() and useNetcapApi() instead of Next.js hooks

export { default as DashboardPage } from './DashboardPage';
export { default as AlertsPage } from './AlertsPage';
export { default as AnalyzePage } from './AnalyzePage';
export { default as AuditPage } from './AuditPage';
export { default as BPFPage } from './BPFPage';
export { default as CertificatesPage } from './CertificatesPage';
export { default as ConfigPage } from './ConfigPage';
export { default as ConnectionsPage } from './ConnectionsPage';
export { default as CredentialsPage } from './CredentialsPage';
export { default as DbsPage } from './DbsPage';
export { default as DecodersPage } from './DecodersPage';
export { default as DevicesPage } from './DevicesPage';
export { default as DomainsPage } from './DomainsPage';
export { default as DpiPage } from './DpiPage';
export { default as ErrorsPage } from './ErrorsPage';
export { default as ExplorePage } from './ExplorePage';
export { default as FilesPage } from './FilesPage';
export { default as FingerprintsPage } from './FingerprintsPage';
export { default as HarvestersPage } from './HarvestersPage';
export { default as HostsPage } from './HostsPage';
export { default as HttpPage } from './HttpPage';
export { default as InjectPage } from './InjectPage';
export { default as InterfacesPage } from './InterfacesPage';
export { default as LogsPage } from './LogsPage';
export { default as PcapsPage } from './PcapsPage';
export { default as ProbesPage } from './ProbesPage';
export { default as RecordsPage } from './RecordsPage';
export { default as RulesPage } from './RulesPage';
export { default as RulesetsPage } from './RulesetsPage';
export { default as ServicesPage } from './ServicesPage';
export { default as SoftwarePage } from './SoftwarePage';
export { default as VisualizePage } from './VisualizePage';
export { default as VulnerabilitiesPage } from './VulnerabilitiesPage';
