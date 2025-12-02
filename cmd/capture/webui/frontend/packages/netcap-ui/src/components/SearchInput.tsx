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

import { TextField, InputAdornment, IconButton, Tooltip } from '@mui/material';
import { Clear as ClearIcon, Search as SearchIcon } from '@mui/icons-material';

interface SearchInputProps {
  /** Current search query value */
  value: string;
  /** Callback when search value changes */
  onChange: (value: string) => void;
  /** Callback when search is cleared (optional, called after onChange with empty string) */
  onClear?: () => void;
  /** Placeholder text for the input */
  placeholder?: string;
  /** Minimum width of the input */
  minWidth?: number;
  /** data-learn hint for the learn mode */
  learnHint?: string;
  /** Whether to show the search icon on the left */
  showSearchIcon?: boolean;
  /** Additional sx styles */
  sx?: object;
}

/**
 * A reusable search input component with clear button and negation support.
 * 
 * Features:
 * - Clear button (X) on the right side to reset the search
 * - Supports negation with ! prefix (e.g., "!FTP" excludes FTP)
 * - Multiple space-separated terms are OR'd together for positive matches
 * - Consistent styling across all pages
 * 
 * Usage examples:
 * - "HTTP FTP" - matches if HTTP OR FTP appears in any field
 * - "!FTP" - excludes items where FTP appears in any field
 * - "HTTP !FTP" - matches HTTP but excludes if FTP also appears
 */
export default function SearchInput({
  value,
  onChange,
  onClear,
  placeholder = 'Search... (use !term to exclude)',
  minWidth = 300,
  learnHint = 'Search: Filter the table. Use !term to exclude matches (e.g., !FTP excludes FTP). Multiple space-separated terms are OR\'d together.',
  showSearchIcon = true,
  sx = {},
}: SearchInputProps) {
  const handleClear = () => {
    onChange('');
    if (onClear) {
      onClear();
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value);
  };

  return (
    <TextField
      data-learn={learnHint}
      size="small"
      placeholder={placeholder}
      value={value}
      onChange={handleChange}
      sx={{ minWidth, ...sx }}
      InputProps={{
        startAdornment: showSearchIcon ? (
          <InputAdornment position="start">
            <SearchIcon fontSize="small" color="action" />
          </InputAdornment>
        ) : undefined,
        endAdornment: value ? (
          <InputAdornment position="end">
            <Tooltip title="Clear search and show all data">
              <IconButton
                size="small"
                onClick={handleClear}
                edge="end"
                aria-label="clear search"
              >
                <ClearIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </InputAdornment>
        ) : undefined,
      }}
    />
  );
}

