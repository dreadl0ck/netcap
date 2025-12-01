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

import { Box, Chip, Paper, Typography, Tooltip, Collapse, Switch, FormControlLabel } from '@mui/material';
import ClearIcon from '@mui/icons-material/Clear';
import FilterListIcon from '@mui/icons-material/FilterList';
import FilterListOffIcon from '@mui/icons-material/FilterListOff';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';

/**
 * CommunityIDFilterBar - A bar component that displays the currently selected Community IDs
 * and allows users to remove them, clear all filters, or toggle filtering on/off.
 * 
 * This component is designed to be placed in the Layout to show active filters across all pages.
 */
export function CommunityIDFilterBar() {
  const { 
    selectedCommunityIDs, 
    removeCommunityID, 
    clearCommunityIDs, 
    filterCount,
    isFilterEnabled,
    toggleFilterEnabled,
  } = useCommunityIDFilter();

  // Show bar if there are any IDs selected (whether enabled or not)
  const hasSelectedIDs = filterCount > 0;
  
  if (!hasSelectedIDs) {
    return null;
  }

  const communityIDArray = Array.from(selectedCommunityIDs);

  return (
    <Collapse in={hasSelectedIDs}>
      <Paper
        elevation={2}
        sx={{
          p: 1.5,
          mb: 2,
          backgroundColor: 'background.paper',
          border: '1px solid',
          borderColor: isFilterEnabled ? 'primary.main' : 'action.disabled',
          borderRadius: 1,
          opacity: isFilterEnabled ? 1 : 0.8,
          transition: 'all 0.2s ease-in-out',
        }}
        data-learn="Community ID Filter Bar: Shows currently selected Community IDs. Use the toggle to enable/disable filtering without removing IDs. Click X on individual IDs to remove them, or Clear All to remove all filters."
      >
        <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
          {/* Toggle and Label */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mr: 1 }}>
            <Tooltip title={isFilterEnabled ? 'Click to disable filter (keep IDs)' : 'Click to enable filter'}>
              <FormControlLabel
                control={
                  <Switch 
                    size="small" 
                    checked={isFilterEnabled} 
                    onChange={toggleFilterEnabled}
                    color="primary"
                  />
                }
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    {isFilterEnabled ? (
                      <FilterListIcon color="primary" fontSize="small" />
                    ) : (
                      <FilterListOffIcon color="disabled" fontSize="small" />
                    )}
                    <Typography 
                      variant="body2" 
                      color={isFilterEnabled ? 'primary' : 'text.disabled'} 
                      fontWeight="medium"
                    >
                      Community ID Filter ({communityIDArray.length})
                      {!isFilterEnabled && ' (disabled)'}
                    </Typography>
                  </Box>
                }
                sx={{ m: 0 }}
              />
            </Tooltip>
          </Box>
          
          {/* ID Chips */}
          {communityIDArray.map((id) => (
            <Tooltip key={id} title={`Remove "${id}" from filter`}>
              <Chip
                label={id.length > 25 ? `${id.substring(0, 25)}...` : id}
                size="small"
                color={isFilterEnabled ? 'primary' : 'default'}
                variant={isFilterEnabled ? 'filled' : 'outlined'}
                onDelete={() => removeCommunityID(id)}
                deleteIcon={<ClearIcon fontSize="small" />}
                sx={{
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  maxWidth: 300,
                  opacity: isFilterEnabled ? 1 : 0.6,
                  '& .MuiChip-label': {
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  },
                }}
              />
            </Tooltip>
          ))}
          
          {/* Clear All Button */}
          {communityIDArray.length > 1 && (
            <Tooltip title="Clear all Community ID filters">
              <Chip
                label="Clear All"
                size="small"
                variant="outlined"
                color="error"
                onClick={clearCommunityIDs}
                deleteIcon={<ClearIcon fontSize="small" />}
                onDelete={clearCommunityIDs}
                sx={{ ml: 1 }}
              />
            </Tooltip>
          )}
        </Box>
        
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
          {isFilterEnabled 
            ? 'Filtering data by Community ID for cross-tool correlation (Zeek, Suricata, etc.)'
            : 'Filter disabled - toggle on to apply Community ID filtering'
          }
        </Typography>
      </Paper>
    </Collapse>
  );
}

export default CommunityIDFilterBar;

