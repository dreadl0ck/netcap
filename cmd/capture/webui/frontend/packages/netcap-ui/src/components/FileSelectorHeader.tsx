import { useMemo, useCallback } from 'react';
import {
  Box,
  Chip,
  CircularProgress,
  FormControl,
  MenuItem,
  Select,
  Typography,
  type SelectChangeEvent,
} from '@mui/material';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import { formatBytes } from '../lib/api';
import type { FileInfo, StatusResponse } from '../lib/api';

// Extract sx styles to constants for performance optimization
const SELECT_SX = {
  color: 'inherit',
  '.MuiOutlinedInput-notchedOutline': {
    borderColor: 'rgba(255, 255, 255, 0.23)',
  },
  '&:hover .MuiOutlinedInput-notchedOutline': {
    borderColor: 'rgba(255, 255, 255, 0.4)',
  },
  '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
    borderColor: 'primary.light',
  },
  '.MuiSelect-icon': {
    color: 'inherit',
  },
  '& .MuiSelect-select': {
    display: 'flex',
    alignItems: 'center',
  },
};

const FILE_NAME_SX = {
  fontFamily: 'monospace',
  fontSize: '0.85rem',
  color: 'inherit',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  flex: 1,
  minWidth: 0,
};

const MENU_ITEM_FILE_NAME_SX = {
  fontFamily: 'monospace',
  fontSize: '0.85rem',
  flex: 1,
  overflow: 'hidden',
  textOverflow: 'ellipsis',
};

const CHIP_SX = {
  height: 20,
  fontSize: '0.7rem',
};

export interface FileSelectorHeaderProps {
  inputFiles: FileInfo[];
  status: StatusResponse | undefined;
  switchingFile: boolean;
  onFileChange: (path: string) => Promise<void>;
  learnHint?: string;
}

/**
 * Shared FileSelectorHeader component used across multiple pages
 * Provides a consistent file selection interface with optimized performance
 */
export function FileSelectorHeader({
  inputFiles,
  status,
  switchingFile,
  onFileChange,
  learnHint = "Capture Selector: Switch between different analyzed PCAP files."
}: FileSelectorHeaderProps) {
  // Memoize completed files computation
  const completedFiles = useMemo(() =>
    (inputFiles?.filter((f) => f.isCompleted) || [])
      .sort((a, b) => a.path.localeCompare(b.path)),
    [inputFiles]
  );

  // Current selected value
  const selectedValue = status?.activeInputFile || completedFiles[0]?.path || '';
  
  // Memoize selected file lookup
  const selectedFile = useMemo(() =>
    completedFiles.find((f) => 
      f.path === selectedValue || 
      f.name === selectedValue || 
      f.path.endsWith('/' + selectedValue)
    ),
    [completedFiles, selectedValue]
  );

  // Memoize change handler
  const handleChange = useCallback(async (event: SelectChangeEvent<string>) => {
    await onFileChange(event.target.value);
  }, [onFileChange]);

  // Memoize renderValue
  const renderValue = useCallback(() => (
    <Box display="flex" alignItems="center" gap={1} minWidth={0} flex={1}>
      <Typography sx={FILE_NAME_SX}>
        {selectedFile?.name}
      </Typography>
    </Box>
  ), [selectedFile]);

  // Don't render if only one file or no file selected
  if (completedFiles.length <= 1 || !selectedFile) {
    return null;
  }

  return (
    <FormControl size="small" disabled={switchingFile} sx={{ minWidth: 300, maxWidth: 400 }}>
      <Select
        data-learn={learnHint}
        value={selectedValue}
        onChange={handleChange}
        startAdornment={
          switchingFile ? (
            <CircularProgress size={20} sx={{ mr: 1, color: 'inherit' }} />
          ) : (
            <SwapHorizIcon sx={{ mr: 1, color: 'inherit' }} />
          )
        }
        renderValue={renderValue}
        sx={SELECT_SX}
      >
        {completedFiles.map((file) => (
          <MenuItem key={file.path} value={file.path}>
            <Box display="flex" alignItems="center" gap={1} width="100%">
              {selectedValue === file.path && (
                <Chip
                  data-learn="Active File Indicator: Shows which PCAP file is currently being analyzed."
                  label="Active"
                  size="small"
                  color="success"
                  sx={CHIP_SX}
                />
              )}
              <Typography sx={MENU_ITEM_FILE_NAME_SX}>
                {file.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {formatBytes(file.size)}
              </Typography>
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}

export default FileSelectorHeader;


