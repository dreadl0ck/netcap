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

/**
 * ExamplePage - Demonstrates how to create pages using the Netcap UI library
 * 
 * This is an example page that shows the pattern for creating pages that
 * can be used both within Next.js and in other React frameworks.
 * 
 * Key patterns demonstrated:
 * - Using useNetcapRouter() instead of useRouter()
 * - Using useNetcapApi() instead of importing api directly
 * - Using Layout component that works with any router
 * - Using FileSelectorHeader for file selection
 */

import { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Paper,
  Alert,
  CircularProgress,
} from '@mui/material';


import { useNetcapRouter } from '../hooks/useNetcapRouter';
import { useNetcapApi } from '../hooks/useNetcapApi';
import { Layout } from '../components/Layout';
import { FileSelectorHeader } from '../components/FileSelectorHeader';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";
import { usePresentationSWR as useSWR, mutatePresentation as globalMutate } from "../lib/i18n";
import { translate } from "../lib/i18n";
import { message as finalCopyMessage } from "../lib/i18n";





export interface ExamplePageProps {
  /** Optional title override */
  title?: string;
}

export function ExamplePage({ title = translate("ui:m_4c62ec2ba821269f1494") }: ExamplePageProps) {
  const __uiLocale = useUILocale();
  const router = useNetcapRouter();
  const api = useNetcapApi();
  const [switchingFile, setSwitchingFile] = useState(false);

  // Fetch status and input files
  const { data: status, mutate: mutateStatus } = useSWR('status', () => api.getStatus());
  const { data: inputFiles } = useSWR('inputFiles', () => api.getInputFiles());
  const { data: version } = useSWR('version', () => api.getVersion());

  // Handle file change
  const handleFileChange = useCallback(async (filePath: string) => {
    setSwitchingFile(true);
    try {
      const result = await api.setActiveDirectory(filePath);
      console.log('Directory changed to:', result.outputDir);
      
      await mutateStatus();
      await globalMutate('status');
      
      window.dispatchEvent(new CustomEvent('directory-changed', { detail: result }));
    } catch (err) {
      console.error('Failed to switch file:', err);
      alert(i18nText("ui:m_7ab800e4d59917b1d34c"));
    } finally {
      setSwitchingFile(false);
    }
  }, [api, mutateStatus, __uiLocale]);

  // File selector for header
  const fileSelector = (
    <FileSelectorHeader inputFiles={inputFiles || []}
      status={status}
      switchingFile={switchingFile}
      onFileChange={handleFileChange}
      learnHint={finalCopyMessage("ui:m_451bce0dfff5c0d68499")} />
  );

  return (
    <Layout title={title} headerAction={fileSelector}><Box sx={{ minWidth: 0 }}><Paper sx={{ p: 3, mb: 3 }}><Typography variant="h6" gutterBottom>
            {i18nText("ui:m_6f5e94b0704b8b7531de")}
          </Typography><Typography variant="body1" paragraph>
            {i18nText("ui:m_0214498ae48231b64678")}
          </Typography>{version ? (
            <Alert severity="info" sx={{ mt: 2 }}>
              {i18nRichText("ui:m_88f0da486ba38cd33022", { arg0: String(version.version), arg1: version.commit })}
            </Alert>
          ) : (
            <Box display="flex" alignItems="center" gap={1} sx={{ mt: 2 }}><CircularProgress size={20} /><Typography variant="body2" color="text.secondary">
                {i18nText("ui:m_5e9feae412f97ce48c63")}
              </Typography></Box>
          )}</Paper><Paper sx={{ p: 3 }}><Typography variant="h6" gutterBottom>
            {i18nText("ui:m_e61d88bd9622d6fab6b1")}
          </Typography><Box component="pre" sx={{ 
            p: 2, 
            backgroundColor: 'background.default',
            borderRadius: 1,
            overflow: 'auto',
          }}><code>{JSON.stringify({
                pathname: router.pathname,
                query: router.query,
                isReady: router.isReady,
              }, null, 2)}</code></Box></Paper></Box></Layout>
  );
}

export default ExamplePage;

