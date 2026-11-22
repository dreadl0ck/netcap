import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";


export interface HostIdentityData {
  state: string;
  report?: {
    schema: number; overflow: number; unscopedRecords: number; limitations: string[];
    hosts: { ip: string; scope: string; hostname?: string; hostnameState: string;
      mac?: string; macState: string; evidence: unknown[]; accounts: unknown[]; bindings: unknown[] }[];
  };
}

export default function HostIdentity({ identity, ip }: { identity?: HostIdentityData; ip: string }) {
  const __uiLocale = useUILocale();
  const report = identity?.report;
  const hosts = report?.hosts.filter(host => host.ip === ip) || [];
  return <Box sx={{ my: 2 }}><Typography variant="h6">{i18nText("ui:m_489861264059e4d5fe97")}</Typography><Alert severity="info">{i18nText("ui:m_816238b4279c62460915")}</Alert>{!report || identity?.state !== 'available' ? <Typography>{i18nText("ui:m_c6d52f1cde50166e3003")}</Typography> : <><Typography>{i18nRichText("ui:m_327e9b489eb8d43b2bfc", { arg0: report.overflow, arg1: report.unscopedRecords })}</Typography>{report.limitations?.map((limitation, i) => <Typography key={i} variant="body2">{limitation}</Typography>)}{hosts.length === 0 && <Typography>{i18nText("ui:m_8d15951668c3f1e7f13e")}</Typography>}{hosts.map((host, i) => <Box key={`${host.scope}:${i}`} sx={{ mt: 1 }}><Typography>{i18nRichText("ui:m_e9417c5bbab5ba483669", { arg0: host.scope || i18nText("ui:m_ddddc9fec2c62ce5d4b3") })}</Typography><Typography>{i18nRichText("ui:m_b197dac907954f035605", { arg0: host.hostname || i18nText("ui:m_ddddc9fec2c62ce5d4b3"), arg1: host.hostnameState, arg2: host.mac || i18nText("ui:m_ddddc9fec2c62ce5d4b3"), arg3: host.macState })}</Typography><details><summary>{i18nText("ui:m_c60533283c68f9cd11fe")}</summary><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify({ evidence: host.evidence, accounts: host.accounts, bindings: host.bindings }, null, 2)}</Box></details></Box>)}</>}</Box>;
}
