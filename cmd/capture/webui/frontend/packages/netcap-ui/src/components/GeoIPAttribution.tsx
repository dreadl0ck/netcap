import { Link, Typography } from '@mui/material';

export default function GeoIPAttribution() {
  return (
    <Typography component="footer" variant="caption" color="text.secondary" sx={{ display: 'block', mt: 3 }}>
      GeoIP sources: <Link href="https://db-ip.com" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</Link> (<Link href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">CC BY 4.0</Link>, includes <Link href="https://www.geonames.org" target="_blank" rel="noreferrer">GeoNames</Link>); optional MaxMind GeoLite2. The selected provider order is shown in Databases.
    </Typography>
  );
}
