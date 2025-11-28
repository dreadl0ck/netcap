import { useState, useEffect } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  IconButton,
  Link,
  List,
  ListItem,
  ListItemText,
  TextField,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import InfoIcon from '@mui/icons-material/Info';
import SaveIcon from '@mui/icons-material/Save';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import useSWR from 'swr';
import Layout from '../components/Layout';
import { useNetcapApi } from '../hooks';
import BPFExpressionHighlight, { BPFExpressionBlock } from '../components/BPFExpressionHighlight';
import { SyntaxHighlightedTextArea } from '../components/SyntaxHighlightedInput';

export default function BPF() {
  const api = useNetcapApi();
  const { data: bpfData, error: bpfError, mutate: mutateBPF } = useSWR('bpfInfo', () => api.getBPFInfo());
  const [bpfFilter, setBpfFilter] = useState('');
  const [bpfSaving, setBpfSaving] = useState(false);
  const [bpfErrorMsg, setBpfErrorMsg] = useState<string | null>(null);
  const [bpfSuccess, setBpfSuccess] = useState<string | null>(null);

  // Initialize BPF filter from loaded data
  useEffect(() => {
    if (bpfData) {
      setBpfFilter(bpfData.currentFilter);
    }
  }, [bpfData]);

  const handleBPFSave = async () => {
    setBpfSaving(true);
    setBpfErrorMsg(null);
    setBpfSuccess(null);

    try {
      const result = await api.saveBPFConfig({ filter: bpfFilter });
      setBpfSuccess(result.message);
      mutateBPF();
      // Clear success message after 3 seconds
      setTimeout(() => setBpfSuccess(null), 3000);
    } catch (err) {
      setBpfErrorMsg(err instanceof Error ? err.message : 'Failed to save BPF filter');
    } finally {
      setBpfSaving(false);
    }
  };

  const handleCopyExample = (filter: string) => {
    setBpfFilter(filter);
    navigator.clipboard.writeText(filter);
  };

  if (bpfError) {
    return (
      <Layout title="BPF Filter Configuration">
        <Alert severity="error">
          Failed to load BPF configuration: {bpfError.message}
        </Alert>
      </Layout>
    );
  }

  if (!bpfData) {
    return (
      <Layout title="BPF Filter Configuration">
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
          <CircularProgress />
        </Box>
      </Layout>
    );
  }

  return (
    <Layout title="BPF Filter Configuration">
      <Box sx={{ minWidth: 0 }}>
      {bpfSuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {bpfSuccess}
        </Alert>
      )}
      {bpfErrorMsg && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setBpfErrorMsg(null)}>
          {bpfErrorMsg}
        </Alert>
      )}

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ mb: 3 }}>
            <SyntaxHighlightedTextArea
              syntaxType="bpf"
              value={bpfFilter}
              onChange={setBpfFilter}
              label="Current Filter"
              placeholder="Enter BPF filter expression (e.g., tcp port 80 or udp port 53)"
              rows={4}
              fullWidth
              data-learn="BPF Filter Expression: Enter a Berkeley Packet Filter expression to capture only specific network traffic (e.g., tcp port 80, host 192.168.1.1, or complex combinations)."
            />
            <Box sx={{ mt: 2, display: 'flex', gap: 2, alignItems: 'center' }}>
              <Button
                data-learn="Save Filter: Apply this BPF filter to future packet captures, limiting captured traffic to only packets matching the filter expression."
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleBPFSave}
                disabled={bpfSaving}
              >
                {bpfSaving ? 'Saving...' : 'Save Filter'}
              </Button>
              <Button
                data-learn="Clear Filter: Remove the current BPF filter to capture all network traffic without filtering."
                variant="outlined"
                onClick={() => setBpfFilter('')}
                disabled={!bpfFilter}
              >
                Clear Filter
              </Button>
              <Box sx={{ flex: 1 }} />
              <Link
                data-learn="BPF Documentation: Open the official Berkeley Packet Filter syntax documentation to learn about filter expressions, operators, and advanced filtering techniques."
                href={bpfData.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
              >
                <OpenInNewIcon fontSize="small" />
                BPF Syntax Documentation
              </Link>
            </Box>
          </Box>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Common BPF Filter Examples
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" color="text.secondary" paragraph>
                Click on an example to copy it to the filter field:
              </Typography>
              <List>
                {bpfData.examples.map((example) => (
                  <ListItem
                    data-learn="Filter Example: Click to copy this pre-configured BPF filter expression to the editor for quick use or modification."
                    key={`${example.name}-${example.filter}`}
                    sx={{
                      border: 1,
                      borderColor: 'divider',
                      borderRadius: 1,
                      mb: 1,
                      '&:hover': {
                        bgcolor: 'action.hover',
                        cursor: 'pointer',
                      },
                    }}
                    onClick={() => handleCopyExample(example.filter)}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                            {example.name}
                          </Typography>
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopyExample(example.filter);
                            }}
                          >
                            <ContentCopyIcon fontSize="small" />
                          </IconButton>
                        </Box>
                      }
                      secondary={
                        <>
                          <Box
                            sx={{
                              display: 'block',
                              bgcolor: 'action.hover',
                              p: 1,
                              borderRadius: 1,
                              my: 1,
                            }}
                          >
                            <BPFExpressionHighlight 
                              expression={example.filter}
                              fontSize="0.9rem"
                              wrap={true}
                            />
                          </Box>
                          <Typography variant="body2" color="text.secondary">
                            {example.description}
                          </Typography>
                        </>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </CardContent>
      </Card>

      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            About BPF Filters
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            BPF (Berkeley Packet Filter) is a powerful packet filtering technology that enables efficient packet capture
            at the kernel level. By applying filters before packets are copied to user space, BPF can significantly
            reduce CPU usage and improve capture performance.
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            BPF filters use a simple expression syntax that can match on various packet attributes including:
          </Typography>
          <List sx={{ pl: 2 }}>
            <ListItem sx={{ py: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                • Protocol types (tcp, udp, icmp, ip, ip6, arp, etc.)
              </Typography>
            </ListItem>
            <ListItem sx={{ py: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                • Ports (port 80, portrange 8000-9000)
              </Typography>
            </ListItem>
            <ListItem sx={{ py: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                • IP addresses (host 192.168.1.1, net 10.0.0.0/8)
              </Typography>
            </ListItem>
            <ListItem sx={{ py: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                • Packet size (greater 1000, less 100)
              </Typography>
            </ListItem>
            <ListItem sx={{ py: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                • Direction (src, dst)
              </Typography>
            </ListItem>
            <ListItem sx={{ py: 0.5 }}>
              <Typography variant="body2" color="text.secondary">
                • Logical operators (and, or, not)
              </Typography>
            </ListItem>
          </List>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            For more information, see the{' '}
            <Link href={bpfData.docsUrl} target="_blank" rel="noopener noreferrer">
              official BPF documentation
            </Link>
            .
          </Typography>
        </CardContent>
      </Card>
      </Box>
    </Layout>
  );
}

