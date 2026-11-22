import { Alert } from '@mui/material';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { translate } from "../lib/i18n";



export interface CertificateAssessmentFields {
  assessmentBasis?: string; assessmentTimeNs?: string; validityState?: string;
  selfSignatureState?: string; certificateSender?: string;
}

export function certificateValidityLabel(cert: CertificateAssessmentFields & { daysUntilExpiration: number }): string {
  if (cert.assessmentBasis !== 'capture-time' || !cert.validityState || cert.validityState === 'unavailable') return translate("ui:m_5d969756ccd47f751c2e");
  if (cert.validityState === 'expired') return translate("ui:m_cd2e9b06a74b3b9f813d");
  if (cert.validityState === 'not-yet-valid') return translate("ui:m_c27f0920d82c39dcd259");
  if (cert.validityState !== 'valid') return translate("ui:m_66dea3b23ae4e18e2473");
  return translate("ui:m_cfa16c145b8996a6381a", { arg0: cert.daysUntilExpiration });
}

export function CertificateAssessmentNotice({ cert }: { cert: CertificateAssessmentFields }) {
  const __uiLocale = useUILocale();
  const known = cert.assessmentBasis === 'capture-time' && cert.validityState && cert.validityState !== 'unavailable';
  return <Alert severity={known ? 'info' : 'warning'}>
    {i18nRichText("ui:m_eec6f9374d248a28ad1d", { arg0: known ? i18nText("ui:m_fecb979a500f113ae1c4", { arg0: cert.validityState, arg1: cert.assessmentTimeNs }) : i18nText("ui:m_326ffe6084c4e58246a8"), arg1: cert.selfSignatureState || i18nText("ui:m_408970d22c6dfa100650"), arg2: cert.certificateSender || i18nText("ui:m_b1b6b391498fb13c454c") })}
  </Alert>;
}

export function RecordSemantics({ data, recordType }: { data: Record<string, unknown>; recordType?: string }) {
  const __uiLocale = useUILocale();
  const kind = recordType?.replace(/^NC_/, '');
  if (kind === 'HTTP' || 'ReassemblyStatus' in data) return <HTTPReassemblyNotice status={String(data.ReassemblyStatus || '')} timestampNs={typeof data.TimestampNs === 'string' ? data.TimestampNs : undefined} />;
  if (kind === 'RDP' || 'NegotiationOutcome' in data) return <Alert severity="info">
    {i18nRichText("ui:m_520b85fef49ea7585527", { arg0: String(data.NegotiationOutcome || i18nText('ui:m_408970d22c6dfa100650')), arg1: String(data.AuthenticationOutcome || translate("ui:m_b1b6b391498fb13c454c")), arg2: data.NegotiatedSecurityKnown ? i18nText("ui:m_78e1d3ba1d03cbc86f25") : i18nText("ui:m_b1b6b391498fb13c454c") })}
  </Alert>;
  return null;
}

export function HTTPReassemblyNotice({ status }: { status?: string; timestampNs?: string }) {
  const __uiLocale = useUILocale();
  return status ? <Alert severity="warning" sx={{ mb: 2 }}>{i18nRichText("ui:m_254e09f1d894781f6bc6", { arg0: status })}</Alert> : null;
}
