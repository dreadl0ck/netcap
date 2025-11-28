import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Typography,
  Alert,
  Box,
  CircularProgress,
} from '@mui/material';
import { api } from '../lib/api';

interface ReportIssueDialogProps {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  filename: string;
}

export default function ReportIssueDialog({ open, onClose, sessionId, filename }: ReportIssueDialogProps) {
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async () => {
    if (!description.trim()) {
      setError('Please provide a description of the issue');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const response = await api.reportIssue(sessionId, description);
      setSuccess(true);
      
      // Wait a moment to show success message, then close and refresh the file list
      setTimeout(() => {
        handleClose();
        // Trigger a refresh of the input files list
        window.dispatchEvent(new CustomEvent('refresh-input-files'));
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit issue report');
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    setDescription('');
    setError(null);
    setSuccess(false);
    setSubmitting(false);
    onClose();
  };

  return (
    <Dialog open={open} onClose={submitting ? undefined : handleClose} maxWidth="md" fullWidth>
      <DialogTitle>Report Issue with PCAP</DialogTitle>
      <DialogContent>
        <Box mb={2}>
          <Typography variant="body2" color="text.secondary">
            File: <strong>{filename}</strong>
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            Issue report submitted successfully! Thank you for your feedback.
          </Alert>
        )}

        {!success && (
          <>
            <Typography variant="body2" color="text.secondary" paragraph>
              Please describe the issue you encountered with this PCAP file. You can use Markdown formatting.
            </Typography>

            <TextField
              data-learn="Issue Description: Provide a detailed description of the issue you encountered with this PCAP file using Markdown formatting."
              multiline
              rows={10}
              fullWidth
              variant="outlined"
              placeholder={`## Issue Description\n\nDescribe the issue here...\n\n## Steps to Reproduce\n\n1. Step one\n2. Step two\n\n## Expected Behavior\n\nWhat you expected to happen...\n\n## Actual Behavior\n\nWhat actually happened...`}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={submitting}
            />

            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              This report will include the PCAP file and all generated netcap data for analysis.
              You can submit up to 5 issue reports per day.
            </Typography>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button data-learn="Cancel: Close the issue report dialog without submitting." onClick={handleClose} disabled={submitting}>
          Cancel
        </Button>
        {!success && (
          <Button
            data-learn="Submit Issue Report: Send the issue report with the PCAP file and generated data for analysis."
            onClick={handleSubmit}
            variant="contained"
            color="error"
            disabled={submitting || !description.trim()}
            startIcon={submitting ? <CircularProgress size={20} /> : null}
          >
            {submitting ? 'Submitting...' : 'Submit Issue Report'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

