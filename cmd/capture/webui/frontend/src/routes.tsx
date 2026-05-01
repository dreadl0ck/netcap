/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { lazy, Suspense } from 'react';
import { Routes, Route } from 'react-router';

const DashboardPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.DashboardPage })));
const AlertsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.AlertsPage })));
const AnalyzePage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.AnalyzePage })));
const AuditPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.AuditPage })));
const BPFPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.BPFPage })));
const CertificatesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.CertificatesPage })));
const ConfigPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ConfigPage })));
const ConnectionsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ConnectionsPage })));
const SecretsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.SecretsPage })));
const DbsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.DbsPage })));
const DecodersPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.DecodersPage })));
const DevicesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.DevicesPage })));
const DomainsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.DomainsPage })));
const DpiPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.DpiPage })));
const ErrorsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ErrorsPage })));
const ExplorePage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ExplorePage })));
const FilesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.FilesPage })));
const YaraPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.YaraPage })));
const FingerprintsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.FingerprintsPage })));
const HarvestersPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.HarvestersPage })));
const HostsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.HostsPage })));
const HttpPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.HttpPage })));
const InjectPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.InjectPage })));
const InterfacesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.InterfacesPage })));
const LogsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.LogsPage })));
const PcapsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.PcapsPage })));
const ProbesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ProbesPage })));
const ProtobufPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ProtobufPage })));
const RecordsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.RecordsPage })));
const RulesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.RulesPage })));
const RulesetsPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.RulesetsPage })));
const ServicesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.ServicesPage })));
const SoftwarePage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.SoftwarePage })));
const VisualizePage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.VisualizePage })));
const VulnerabilitiesPage = lazy(() => import('@dreadl0ck/netcap-ui/pages').then(m => ({ default: m.VulnerabilitiesPage })));

export function AppRoutes() {
  return (
    <Suspense fallback={null}>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/analyze" element={<AnalyzePage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/bpf" element={<BPFPage />} />
        <Route path="/certificates" element={<CertificatesPage />} />
        <Route path="/config" element={<ConfigPage />} />
        <Route path="/connections" element={<ConnectionsPage />} />
        <Route path="/secrets" element={<SecretsPage />} />
        <Route path="/dbs" element={<DbsPage />} />
        <Route path="/decoders" element={<DecodersPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/domains" element={<DomainsPage />} />
        <Route path="/dpi" element={<DpiPage />} />
        <Route path="/errors" element={<ErrorsPage />} />
        <Route path="/explore" element={<ExplorePage />} />
        <Route path="/files" element={<FilesPage />} />
        <Route path="/yara" element={<YaraPage />} />
        <Route path="/fingerprints" element={<FingerprintsPage />} />
        <Route path="/harvesters" element={<HarvestersPage />} />
        <Route path="/hosts" element={<HostsPage />} />
        <Route path="/http" element={<HttpPage />} />
        <Route path="/inject" element={<InjectPage />} />
        <Route path="/interfaces" element={<InterfacesPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/pcaps" element={<PcapsPage />} />
        <Route path="/probes" element={<ProbesPage />} />
        <Route path="/protobuf" element={<ProtobufPage />} />
        <Route path="/records" element={<RecordsPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/rulesets" element={<RulesetsPage />} />
        <Route path="/services" element={<ServicesPage />} />
        <Route path="/software" element={<SoftwarePage />} />
        <Route path="/visualize" element={<VisualizePage />} />
        <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
      </Routes>
    </Suspense>
  );
}
