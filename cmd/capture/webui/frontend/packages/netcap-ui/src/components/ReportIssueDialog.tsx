/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
  IconButton,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { api } from '../lib/api';
import { useIsMobile } from '../hooks';
import { message as i18nMessage, richText as i18nRichText, renderText as i18nRenderText, translate as i18nText, type MessageText as UIMessageText, useLocale as useUILocale } from "../lib/i18n";
import { errorText } from "../lib/i18n";



interface ReportIssueDialogProps {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  filename: string;
}

export default function ReportIssueDialog({ open, onClose, sessionId, filename }: ReportIssueDialogProps) {
  const __uiLocale = useUILocale();
  const isMobile = useIsMobile();
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<UIMessageText | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async () => {
    if (!description.trim()) {
      setError(i18nMessage("ui:m_f2c4fec837dc16e59b06"));
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
      setError(err instanceof Error ? errorText(err) : i18nMessage("ui:m_f0d2d8c9fbbdff8ed2f6"));
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
    <Dialog open={open} onClose={submitting ? undefined : handleClose} maxWidth="md" fullWidth fullScreen={isMobile}><DialogTitle><Box display="flex" justifyContent="space-between" alignItems="center">
          {i18nRichText("ui:m_9eed832eb5b7037384cf", { arg0: isMobile && (
            <IconButton onClick={submitting ? undefined : handleClose} edge="end" disabled={submitting}><CloseIcon /></IconButton>
          ) })}
        </Box></DialogTitle><DialogContent><Box mb={2}><Typography variant="body2" color="text.secondary">
            {i18nRichText("ui:m_d92f6901e5e22d410b51", { arg0: filename, tag0: (chunks: import('react').ReactNode[]) => <strong>{chunks}</strong> })}
          </Typography></Box>{i18nRenderText(error) && (
          <Alert severity="error" sx={{ mb: 2 }}>{i18nRenderText(error)}</Alert>
        )}{success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {i18nText("ui:m_f246f34105c11c3c8686")}
          </Alert>
        )}{!success && (
          <><Typography variant="body2" color="text.secondary" paragraph>
              {i18nText("ui:m_ad15e60f68592bd9109f")}
            </Typography><TextField data-learn={i18nText("ui:m_a6781bf8c1bdc9be3a6b")}
              multiline
              rows={10}
              fullWidth
              variant="outlined"
              placeholder={i18nText("ui:m_6307193d673cd019eccc")}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={submitting} /><Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {i18nText("ui:m_5aac9274e1bc0334c669")}
            </Typography></>
        )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_7b4dc7dfd370661ba2cf")} onClick={handleClose} disabled={submitting}>
          {i18nText("ui:m_0095547326bed510a824")}
        </Button>{!success && (
          <Button data-learn={i18nText("ui:m_4296af22a0db42c7e0d0")}
            onClick={handleSubmit}
            variant="contained"
            color="error"
            disabled={submitting || !description.trim()}
            startIcon={submitting ? <CircularProgress size={20} /> : null}>{submitting ? i18nText("ui:m_2c6514b80ad85a7117cf") : i18nText("ui:m_f127623825b4d277542d")}</Button>
        )}</DialogActions></Dialog>
  );
}

