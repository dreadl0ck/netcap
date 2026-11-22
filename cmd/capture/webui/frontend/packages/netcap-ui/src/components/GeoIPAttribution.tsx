import { Link, Typography } from '@mui/material';
import { richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";


export default function GeoIPAttribution() {
  const __uiLocale = useUILocale();
  return (
    <Typography component="footer" variant="caption" color="text.secondary" sx={{ display: 'block', mt: 3 }}>
      {i18nRichText("ui:m_3795c462d791af9b6fdc", { tag0: (chunks: import('react').ReactNode[]) => <Link href="https://db-ip.com" target="_blank" rel="noreferrer">{chunks}</Link>, tag1: (chunks: import('react').ReactNode[]) => <Link href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">{chunks}</Link>, tag2: (chunks: import('react').ReactNode[]) => <Link href="https://www.geonames.org" target="_blank" rel="noreferrer">{chunks}</Link> })}
    </Typography>
  );
}
