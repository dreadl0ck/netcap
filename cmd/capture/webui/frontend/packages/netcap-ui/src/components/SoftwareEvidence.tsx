import Box from '@mui/material/Box';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { translate } from "../lib/i18n";



export interface SoftwareObservation {
  host: string; role: string; timestampNs: string; vulnerabilityAssessment: string;
}

export default function SoftwareEvidence({ observations, capped }: {
  observations?: SoftwareObservation[]; capped?: boolean;
}) {
  const __uiLocale = useUILocale();
  return <Box sx={{ my: 2 }}>{!observations?.length ? <p>{i18nText("ui:m_f0acb214dc0095b2ad63")}</p> : <details><summary>{i18nRichText("ui:m_3d0718dcb74bc5f707e5", { arg0: observations.length, arg1: capped ? i18nText("ui:m_010f532eef2582a23872") : '' })}</summary><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(observations.map(item => ({
        host: item.host || "unavailable", role: item.role || "unavailable", timestampNs: item.timestampNs,
        vulnerabilityAssessment: item.vulnerabilityAssessment || "unavailable",
      })), null, 2)}</Box></details>}</Box>;
}
