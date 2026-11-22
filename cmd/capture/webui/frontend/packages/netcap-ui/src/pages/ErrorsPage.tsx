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

import { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Typography,
  Alert as MuiAlert,
  IconButton,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import ErrorIcon from '@mui/icons-material/Error';
import RefreshIcon from '@mui/icons-material/Refresh';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CloseIcon from '@mui/icons-material/Close';
import AssessmentIcon from '@mui/icons-material/Assessment';
import Layout from '../components/Layout';
import ResponsiveDataView from '../components/ResponsiveDataView';
import { ErrorLogInfo, AggregatedError, formatBytes } from '../lib/api';
import { useNetcapApi, useIsMobile } from '../hooks';

import { translate as i18nText, richText as i18nRichText, getLocale as getUILocale, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR } from "../lib/i18n";
import { renderError } from "../lib/i18n";
import { type MessageText, message } from "../lib/i18n";
import { renderText } from "../lib/i18n";
import { rawCode } from "../lib/i18n";
import { message as i18nParameterMessage } from "../lib/i18n";








type SortField = 'errorCount' | 'inputFilename' | 'inputFileSize';
type SortOrder = 'asc' | 'desc';

export default function ErrorsPage() {
  const __uiLocale = useUILocale();
  const api = useNetcapApi();
  const isMobile = useIsMobile();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [sortField, setSortField] = useState<SortField>('errorCount');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [selectedError, setSelectedError] = useState<ErrorLogInfo | null>(null);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [errorLogContent, setErrorLogContent] = useState<MessageText>('');
  const [loadingContent, setLoadingContent] = useState(false);
  const [aggregatedDialogOpen, setAggregatedDialogOpen] = useState(false);
  const [aggregatedErrors, setAggregatedErrors] = useState<AggregatedError[]>([]);
  const [loadingAggregated, setLoadingAggregated] = useState(false);

  // Fetch error logs
  const { data: errorLogs, error, mutate: mutateErrorLogs } = useSWR(
    'errorLogs',
    () => api.getErrorLogs(),
    {
      refreshInterval: 10000, // Refresh every 10 seconds
    }
  );

  // Sort error logs
  const sortedErrorLogs = errorLogs ? [...errorLogs].sort((a, b) => {
    let aValue: string | number;
    let bValue: string | number;

    switch (sortField) {
      case 'errorCount':
        aValue = a.errorCount;
        bValue = b.errorCount;
        break;
      case 'inputFilename':
        aValue = a.inputFilename;
        bValue = b.inputFilename;
        break;
      case 'inputFileSize':
        aValue = a.inputFileSize;
        bValue = b.inputFileSize;
        break;
      default:
        aValue = a.errorCount;
        bValue = b.errorCount;
    }

    if (typeof aValue === 'string' && typeof bValue === 'string') {
      return sortOrder === 'asc' ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    }

    return sortOrder === 'asc' ? (aValue as number) - (bValue as number) : (bValue as number) - (aValue as number);
  }) : [];

  // Paginate
  const paginatedErrorLogs = sortedErrorLogs.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleRefresh = () => {
    mutateErrorLogs();
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      // Toggle sort order if clicking the same column
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new column and default to descending
      setSortField(field);
      setSortOrder('desc');
    }
    setPage(0); // Reset to first page when sorting changes
  };

  const handleViewErrors = async (errorLog: ErrorLogInfo) => {
    setSelectedError(errorLog);
    setDetailsDialogOpen(true);
    setLoadingContent(true);
    setErrorLogContent('');

    try {
      // Use sessionId if available (service mode), otherwise use inputFile
      const identifier = errorLog.sessionId || errorLog.inputFile || errorLog.inputFilename;
      const content = await api.getErrorLogContent(identifier);
      setErrorLogContent(content);
    } catch (err) {
      setErrorLogContent(message("ui:m_c0073d3f519362353d3f", { arg0: err instanceof Error ? err.message : i18nParameterMessage("ui:m_3f0f714149c18490a32b") }));
    } finally {
      setLoadingContent(false);
    }
  };

  const handleCloseDialog = () => {
    setDetailsDialogOpen(false);
    setSelectedError(null);
    setErrorLogContent('');
  };

  const handleShowAggregated = async () => {
    setAggregatedDialogOpen(true);
    setLoadingAggregated(true);

    try {
      const errors = await api.getAggregatedErrors();
      setAggregatedErrors(errors);
    } catch (err) {
      console.error('Failed to load aggregated errors:', err);
      setAggregatedErrors([]);
    } finally {
      setLoadingAggregated(false);
    }
  };

  const handleCloseAggregated = () => {
    setAggregatedDialogOpen(false);
    setAggregatedErrors([]);
  };

  return (
    <Layout title={i18nText("ui:m_bf5fde1e287cc132b8e5")}><Box sx={{ minWidth: 0 }}><Box sx={{ 
          display: 'flex', 
          flexDirection: { xs: 'column', sm: 'row' },
          justifyContent: 'space-between', 
          alignItems: { xs: 'stretch', sm: 'center' }, 
          gap: 2,
          mb: 3 
        }}><Box sx={{ flex: 1 }}><Typography variant="body1" fontWeight="medium">
              {i18nRichText("ui:m_0465bb176cb25c88ae4b", { arg0: sortedErrorLogs.length })}
            </Typography><Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              {i18nText("ui:m_26aa67d3f6638911f565")}
            </Typography></Box><Button data-learn={i18nText("ui:m_359ef4fc88dc2363b96f")}
            variant="outlined" 
            startIcon={<RefreshIcon />} 
            onClick={handleRefresh}
            size="small"
            sx={{ alignSelf: { xs: 'stretch', sm: 'center' } }}>
            {i18nText("ui:m_230fc1b63eb3ef4e6a34")}
          </Button></Box>{error && (
          <MuiAlert severity="error" sx={{ mb: 2 }}>
            {i18nRichText("ui:m_8877debfa475cbdddcd5", { arg0: renderError(error) })}
          </MuiAlert>
        )}{!errorLogs && !error && (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress /></Box>
        )}{errorLogs && (
          <>{/* Summary Card */}{sortedErrorLogs.length > 0 && (
              <Card sx={{ mb: 3 }}><CardContent><Box sx={{ 
                    display: 'flex', 
                    flexDirection: { xs: 'column', sm: 'row' },
                    justifyContent: 'space-between', 
                    alignItems: { xs: 'stretch', sm: 'center' },
                    gap: 2
                  }}><Box><Typography color="text.secondary" gutterBottom>
                        {i18nText("ui:m_5f38ca429e0800db468b")}
                      </Typography><Typography variant="h4" color="error">{sortedErrorLogs.reduce((sum, log) => sum + log.errorCount, 0).toLocaleString(getUILocale())}</Typography></Box><Button data-learn={i18nText("ui:m_357df286c9305b3832c2")}
                      variant="contained"
                      startIcon={<AssessmentIcon />}
                      onClick={handleShowAggregated}
                      size="small"
                      sx={{ height: 'fit-content' }}
                      fullWidth={false}>
                      {i18nText("ui:m_acce15e9fe572e2c8190")}
                    </Button></Box></CardContent></Card>
            )}{/* Errors Table */}<ResponsiveDataView data={paginatedErrorLogs}
              totalCount={sortedErrorLogs.length}
              page={page}
              rowsPerPage={rowsPerPage}
              onPageChange={handleChangePage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
              onCardClick={(errorLog: ErrorLogInfo) => handleViewErrors(errorLog)}
              renderCard={(errorLog: ErrorLogInfo) => (
                <Card variant="outlined"><CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}><ErrorIcon color="error" fontSize="small" sx={{ flexShrink: 0 }} /><Typography variant="subtitle2"
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '0.8rem',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          flex: 1,
                        }}>{errorLog.inputFilename}</Typography></Box><Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}><Typography variant="caption" color="text.secondary">
                        {i18nRichText("ui:m_17039e3355ec467a7598", { arg0: formatBytes(errorLog.inputFileSize) })}
                      </Typography><Chip label={i18nText("ui:m_6c98ad8b9a74389a1795", { arg0: errorLog.errorCount })}
                        size="small"
                        color="error"
                        sx={{ fontWeight: 'bold' }} /></Box></CardContent></Card>
              )}
              desktopTable={<TableContainer component={Paper} sx={{ overflowX: 'auto', maxWidth: '100%' }}><Table sx={{ minWidth: { xs: 600, md: 'auto' } }}><TableHead><TableRow><TableCell><TableSortLabel active={sortField === 'inputFilename'}
                        direction={sortField === 'inputFilename' ? sortOrder : 'asc'}
                        onClick={() => handleSort('inputFilename')}>
                        {i18nText("ui:m_14abb320dab59e7a0668")}
                      </TableSortLabel></TableCell><TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}><TableSortLabel active={sortField === 'inputFileSize'}
                        direction={sortField === 'inputFileSize' ? sortOrder : 'asc'}
                        onClick={() => handleSort('inputFileSize')}>
                        {i18nText("ui:m_9f6d1222a5b4e2fbbf4d")}
                      </TableSortLabel></TableCell><TableCell><TableSortLabel active={sortField === 'errorCount'}
                        direction={sortField === 'errorCount' ? sortOrder : 'asc'}
                        onClick={() => handleSort('errorCount')}>
                        {i18nText("ui:m_01f10ea0c23b439df3f0")}
                      </TableSortLabel></TableCell><TableCell>{i18nText("ui:m_8b59af6a47204b74041c")}</TableCell></TableRow></TableHead><TableBody>{paginatedErrorLogs.length === 0 ? (
                    <TableRow><TableCell colSpan={4} align="center"><Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                          {i18nText("ui:m_28448b4e5bc137e2a661")}
                        </Typography></TableCell></TableRow>
                  ) : (
                    paginatedErrorLogs.map((errorLog) => (
                      <TableRow key={errorLog.inputFilename} 
                        hover 
                        onClick={() => handleViewErrors(errorLog)}
                        sx={{ cursor: 'pointer' }}><TableCell><Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}><ErrorIcon color="error" fontSize="small" sx={{ flexShrink: 0 }} /><Typography variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                fontSize: '0.85rem',
                                maxWidth: { xs: 200, sm: 300, md: 400 },
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}>{errorLog.inputFilename}</Typography></Box></TableCell><TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}><Typography variant="body2">{formatBytes(errorLog.inputFileSize)}</Typography></TableCell><TableCell><Chip label={errorLog.errorCount.toLocaleString(getUILocale())}
                            size="small"
                            color="error"
                            sx={{ fontWeight: 'bold' }} /></TableCell><TableCell><Button data-learn={i18nText("ui:m_536b1718b48e4433cc38")}
                            size="small"
                            variant="outlined"
                            startIcon={<VisibilityIcon />}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleViewErrors(errorLog);
                            }}>
                            {i18nText("ui:m_6f8350825a150a1e4bf0")}
                          </Button></TableCell></TableRow>
                    ))
                  )}</TableBody></Table></TableContainer>} /></>
        )}{/* Error Details Dialog */}<Dialog open={detailsDialogOpen}
          onClose={handleCloseDialog}
          maxWidth="lg"
          fullWidth
          fullScreen={isMobile}><DialogTitle><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><Box>
                {i18nRichText("ui:m_c77b05ed1cb35ee6aa2b", { arg0: selectedError?.inputFilename })}
              </Box>{isMobile && (
                <IconButton onClick={handleCloseDialog} edge="end"><CloseIcon /></IconButton>
              )}</Box></DialogTitle><DialogContent>{selectedError && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}><Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}><Chip label={i18nText("ui:m_6c98ad8b9a74389a1795", { arg0: selectedError.errorCount })}
                    size="small"
                    color="error" /><Typography variant="body2" color="text.secondary">
                    {i18nRichText("ui:m_35b24eed84e1a87ac262", { arg0: formatBytes(selectedError.inputFileSize) })}
                  </Typography></Box><Box><Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    {i18nText("ui:m_34cdab9d0b1f20c850ae")}
                  </Typography>{loadingContent ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress /></Box>
                  ) : (
                    <Paper sx={{
                        p: 2,
                        backgroundColor: 'background.default',
                        overflow: 'auto',
                        maxHeight: 500,
                      }}><pre style={{
                          margin: 0,
                          fontFamily: 'var(--netcap-mono, monospace)',
                          fontSize: '0.85rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                          color: 'inherit',
                        }}>{renderText(errorLogContent) || rawCode("No content available")}</pre></Paper>
                  )}</Box></Box>
            )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_79a14bda74135029047d")} onClick={handleCloseDialog}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog>{/* Aggregated Errors Dialog */}<Dialog open={aggregatedDialogOpen}
          onClose={handleCloseAggregated}
          maxWidth="lg"
          fullWidth
          fullScreen={isMobile}><DialogTitle><Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><Box>
                {i18nText("ui:m_f85bd1817ef8b4f4f1ad")}
              </Box>{isMobile && (
                <IconButton onClick={handleCloseAggregated} edge="end"><CloseIcon /></IconButton>
              )}</Box></DialogTitle><DialogContent>{loadingAggregated ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress /></Box>
            ) : aggregatedErrors.length === 0 ? (
              <Box sx={{ p: 4, textAlign: 'center' }}><Typography variant="body2" color="text.secondary">
                  {i18nText("ui:m_03422f0f20b5dac0795f")}
                </Typography></Box>
            ) : (
              <Box><Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 2 }}>
                  {i18nRichText("ui:m_d107eb1c37de27971829", { arg0: aggregatedErrors.length })}
                </Typography><Paper sx={{ maxHeight: 600, overflow: 'auto' }}><List>{aggregatedErrors.map((error, index) => (
                      <ListItem key={error.errorMessage}
                        sx={{
                          borderBottom: index < aggregatedErrors.length - 1 ? '1px solid' : 'none', borderColor: 'divider',
                          '&:hover': { backgroundColor: 'action.hover' },
                        }}><ListItemText primary={<Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}><Chip label={`[${error.count}]`}
                                size="small"
                                color="error"
                                sx={{ fontWeight: 'bold', minWidth: 60 }} /><Typography variant="body2"
                                sx={{
                                  fontFamily: 'monospace',
                                  fontSize: '0.9rem',
                                  flex: 1,
                                  wordBreak: 'break-word',
                                }}>{error.errorMessage}</Typography></Box>}
                          secondary={error.firstSeen && (
                              <Typography variant="caption" color="text.secondary">
                                {i18nRichText("ui:m_05f3830fc17fa6324c6d", { arg0: error.firstSeen })}
                              </Typography>
                            )} /></ListItem>
                    ))}</List></Paper></Box>
            )}</DialogContent><DialogActions><Button data-learn={i18nText("ui:m_d386f3f19fb468865e3f")} onClick={handleCloseAggregated}>{i18nText("ui:m_a695258f28d817037ea8")}</Button></DialogActions></Dialog></Box></Layout>
  );
}
