import { useEffect, useState } from 'react';
import { Alert, Box, Button, Chip, CircularProgress, Link, Paper, Stack, TextField, Typography } from '@mui/material';

import Layout from '../components/Layout';
import { useNetcapApi, useNetcapRouter } from '../hooks';
import { behaviorSelection } from '../lib/behavior';
import type { ServiceSignatureInventory } from '../lib/api';
import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { renderError } from "../lib/i18n";




function Inventory({ title, inventory }: { title: string; inventory: ServiceSignatureInventory }) {
  const __uiLocale = useUILocale();
  return <Paper variant="outlined" sx={{ p: 2, overflowWrap: 'anywhere' }}><Stack spacing={1}><Typography variant="h6">{title}</Typography><Typography>{i18nRichText("removed:m_228b6e64ebd1956bcfba", { arg0: inventory.state, arg1: inventory.source, arg2: inventory.rule_count, arg3: inventory.protocols.join(', ') || i18nText("removed:m_cbd2cdb27245f246335d") })}</Typography>{inventory.warning && <Alert severity="warning">{inventory.warning}</Alert>}<Typography variant="body2">{i18nRichText("removed:m_d071666729f9b4936568", { arg0: new Date(inventory.checked_at).toLocaleString(getUILocale()) })}</Typography>{inventory.source_sha256 && <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{i18nRichText("removed:m_2524d29776ba2149b66b", { arg0: inventory.source_sha256 })}</Typography>}{inventory.limitations.map(text => <Typography key={text} variant="body2" color="text.secondary">{text}</Typography>)}</Stack></Paper>;
}

export default function ServiceSignatures() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const router = useNetcapRouter();
  const query = router.getQueryParam('search') ?? '';
  const [search, setSearch] = useState(query);
  useEffect(() => setSearch(query), [query]);
  const { data, error, mutate } = useSWR('service-signatures', () => api.getServiceSignatures());
  const { data: status } = useSWR('status', () => api.getStatus());
  const { data: files } = useSWR('inputFiles', () => api.getInputFiles());
  const selection = behaviorSelection(status, files);
  const { data: run, error: runError, mutate: refreshRun } = useSWR(
    ['service-signature-status', selection], () => api.getServiceSignatureStatus(selection), { keepPreviousData: false },
  );
  const displayedCatalogue = run?.catalogue ?? data?.catalogue;
  const rules = displayedCatalogue?.rules.filter(rule => `${rule.id} ${rule.protocol} ${rule.kind}`.toLowerCase().includes(search.toLowerCase())) ?? [];

  return <Layout title={i18nText("removed:m_3d53ce1688d1bda2d5f7")}><Stack spacing={2} sx={{ p: 3 }}><Typography variant="body2">{i18nText("removed:m_359a11063ffd8ad1c9d1")}</Typography><Alert severity="info">{i18nText("removed:m_a345ce7f756a8364964a")}</Alert><Box><Button variant="outlined" onClick={() => { void mutate(); void refreshRun(); }}>{i18nText("removed:m_3d6e9b60c1ebbcd14acb")}</Button></Box>{error && <Alert severity="error">{i18nRichText("removed:m_fa83a31a8e3be53e2933", { arg0: error instanceof Error ? renderError(error) : i18nText("removed:m_3f0f714149c18490a32b") })}</Alert>}{!data && !error && <Box role="status" aria-label={i18nText("removed:m_1f9d44110746368d3f03")}><CircularProgress /></Box>}{data?.inventory && <Inventory title={i18nText("removed:m_d21e1a7a0c67e296108b")} inventory={data.inventory} />}<Typography variant="body2" color="text.secondary">{i18nText("removed:m_28907984ab0e2382a3d5")}</Typography>{run && <Inventory title={i18nText("removed:m_93b5f2fdfd5c3640fa35")} inventory={run} />}{runError && <Alert severity="warning">{i18nRichText("removed:m_9005138b70d517f9f1ab", { arg0: runError instanceof Error ? renderError(runError) : i18nText("removed:m_6a4919054821d50e870d") })}</Alert>}<TextField label={i18nText("removed:m_1b22836f6093d6e975cb")} value={search} onChange={e => setSearch(e.target.value)} fullWidth />{displayedCatalogue && <Typography>{i18nRichText("removed:m_6ac407f8a7b2a0e7bf63", { arg0: rules.length, arg1: displayedCatalogue.rules.length, arg2: displayedCatalogue.schema_version, arg3: run?.catalogue ? i18nText("removed:m_76e382886e4834d49597") : i18nText("removed:m_3bae966976b3a10e41c5") })}</Typography>}{displayedCatalogue && rules.length === 0 && <Alert severity="info">{i18nText("removed:m_7ad1b3fea4c40294c7cf")}</Alert>}{rules.map(rule => <Paper component="article" key={rule.id} variant="outlined" sx={{ p: 2, overflowWrap: 'anywhere' }}><Stack spacing={1}><Typography variant="h6" sx={{ fontFamily: 'monospace' }}>{rule.id}</Typography><Stack direction="row" spacing={1} useFlexGap flexWrap="wrap"><Chip label={rule.protocol} /><Chip label={rule.transport} /><Chip label={rule.direction} /></Stack><Typography>{i18nRichText("removed:m_770c9938b1338bc81f7a", { arg0: rule.kind })}</Typography><Typography variant="subtitle2">{i18nText("removed:m_810d56fef512155aad2e")}</Typography>{rule.provenance.map((source, index) => <Typography key={`${source.url}-${index}`} variant="body2">{source.url.startsWith('https://') ? <Link href={source.url} target="_blank" rel="noopener noreferrer">{source.section}</Link> : source.section}— {source.url}</Typography>)}</Stack></Paper>)}</Stack></Layout>;
}
