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

import { Chip, Tooltip, Box, Typography } from '@mui/material';
import FilterListIcon from '@mui/icons-material/FilterList';
import CheckIcon from '@mui/icons-material/Check';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

interface CommunityIDChipProps {
  /** The Community ID value */
  communityId: string;
  /** Display mode: 'chip' renders as a chip, 'text' renders as clickable text */
  mode?: 'chip' | 'text';
  /** Optional custom label (defaults to the communityId value) */
  label?: string;
  /** Whether to show only a truncated version */
  truncate?: boolean;
}

/**
 * CommunityIDChip - A clickable component for Community IDs that adds them to a global filter.
 * 
 * Clicking the chip toggles the Community ID in the global filter, allowing users
 * to filter all data pages by one or more Community IDs for cross-tool correlation.
 */
export function CommunityIDChip({ communityId, mode = 'chip', label, truncate = false }: CommunityIDChipProps) {
  const { toggleCommunityID, isCommunityIDSelected } = useCommunityIDFilter();
  
  const isSelected = isCommunityIDSelected(communityId);
  const displayLabel = label || (truncate ? `${communityId.substring(0, 20)}...` : communityId);
  
  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    toggleCommunityID(communityId);
  };

  const tooltipTitle = isSelected 
    ? `Click to remove "${communityId}" from filter` 
    : `Click to filter all pages by Community ID "${communityId}"`;

  if (mode === 'text') {
    return (
      <Tooltip title={tooltipTitle}>
        <Typography
          component="span"
          onClick={handleClick}
          sx={{
            fontFamily: 'monospace',
            fontSize: '0.85rem',
            color: isSelected ? 'primary.main' : 'info.main',
            cursor: 'pointer',
            wordBreak: 'break-all',
            fontWeight: isSelected ? 'bold' : 'normal',
            textDecoration: isSelected ? 'underline' : 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 0.5,
            '&:hover': {
              color: 'primary.main',
              textDecoration: 'underline',
            },
          }}
          data-learn="Community ID: Click to filter all data pages by this Community ID for cross-tool correlation with Zeek, Suricata, etc."
        >
          {isSelected && <CheckIcon sx={{ fontSize: '0.9rem' }} />}
          {displayLabel}
          {!isSelected && <FilterListIcon sx={{ fontSize: '0.9rem', ml: 0.5, opacity: 0.7 }} />}
        </Typography>
      </Tooltip>
    );
  }

  return (
    <Tooltip title={tooltipTitle}>
      <Chip
        label={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {isSelected && <CheckIcon sx={{ fontSize: '0.8rem' }} />}
            <span>{displayLabel}</span>
            {!isSelected && <FilterListIcon sx={{ fontSize: '0.8rem', opacity: 0.7 }} />}
          </Box>
        }
        size="small"
        color={isSelected ? 'primary' : 'info'}
        variant={isSelected ? 'filled' : 'outlined'}
        onClick={handleClick}
        sx={{
          fontFamily: 'monospace',
          fontSize: '0.75rem',
          cursor: 'pointer',
          '&:hover': {
            backgroundColor: isSelected ? 'primary.dark' : 'action.hover',
          },
        }}
        data-learn="Community ID: Click to filter all data pages by this Community ID for cross-tool correlation with Zeek, Suricata, etc."
      />
    </Tooltip>
  );
}

export default CommunityIDChip;

