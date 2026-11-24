import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import { useNetcapConfig, useNetcapLink } from '../providers/NetcapProvider';
import { formatNumber, localeURL, usePresentationSWR } from '../lib/i18n';

interface Story {
  title: string;
  summary: string;
  findings: {rule: string; name: string; count: number}[] | null;
  record?: string;
  partial: boolean;
}

export function ShowcaseStory({ sessionId }: {sessionId?: string}) {
  const Link = useNetcapLink();
  const { backendUrl, fetch = globalThis.fetch } = useNetcapConfig();
  const { data } = usePresentationSWR<Story | null>(sessionId ? ['showcase-story', sessionId] : null, async () => {
    const response = await fetch(localeURL(`${backendUrl}/api/showcase-story?sessionId=${encodeURIComponent(sessionId!)}`));
    if (!response.ok) return null;
    return response.json();
  }, { revalidateOnFocus: false });
  if (!sessionId || !data) return null;
  return <Card variant="outlined" sx={{ mb: 3 }} component="section" aria-labelledby="showcase-title">
    <CardContent>
      <Typography id="showcase-title" component="h2" variant="h6">{data.title}</Typography>
      <Typography variant="body2" sx={{ maxWidth: '70ch', mt: 1 }}>{data.summary}</Typography>
      {!!data.findings?.length && <Box component="ul" sx={{ pl: 2.5, mb: 0, '& li + li': { mt: 0.75 } }}>
        {data.findings.map(finding => <li key={finding.rule}>
          <Link href={`/alerts?sessionId=${encodeURIComponent(sessionId)}&rule=${encodeURIComponent(finding.rule)}`}>{finding.name}</Link>
          <Typography component="span" variant="body2" color="text.secondary"> · {formatNumber(finding.count)}</Typography>
        </li>)}
      </Box>}
      {data.record && <Box mt={1.5}><Link href={`/records?sessionId=${encodeURIComponent(sessionId)}&type=${encodeURIComponent(data.record)}`}>{data.record} records</Link></Box>}
      {data.partial && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>Only part of the alert evidence is indexed.</Typography>}
    </CardContent>
  </Card>;
}
