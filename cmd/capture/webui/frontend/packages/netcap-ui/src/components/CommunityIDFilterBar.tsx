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
import { Box, Chip, Paper, Typography, Tooltip, Collapse, Switch, FormControlLabel } from '@mui/material';
import ClearIcon from '@mui/icons-material/Clear';
import FilterListIcon from '@mui/icons-material/FilterList';
import FilterListOffIcon from '@mui/icons-material/FilterListOff';
import { useCommunityIDFilter } from '../contexts/CommunityIDFilterContext';
import { useIsMobile } from '../hooks/useIsMobile';
import { translate as i18nText, richText as i18nRichText, useLocale as useUILocale } from "../lib/i18n";


/**
 * CommunityIDFilterBar - A bar component that displays the currently selected Community IDs
 * and allows users to remove them, clear all filters, or toggle filtering on/off.
 * 
 * This component is designed to be placed in the Layout to show active filters across all pages.
 */
export function CommunityIDFilterBar() {
  const __uiLocale = useUILocale();
  const { 
    selectedCommunityIDs, 
    removeCommunityID, 
    clearCommunityIDs, 
    filterCount,
    isFilterEnabled,
    toggleFilterEnabled,
  } = useCommunityIDFilter();

  const isMobile = useIsMobile();
  const [showAllChips, setShowAllChips] = useState(false);

  // Show bar if there are any IDs selected (whether enabled or not)
  const hasSelectedIDs = filterCount > 0;

  if (!hasSelectedIDs) {
    return null;
  }

  const communityIDArray = Array.from(selectedCommunityIDs);
  const maxVisibleChips = isMobile && !showAllChips ? 3 : communityIDArray.length;
  const visibleChips = communityIDArray.slice(0, maxVisibleChips);
  const hiddenCount = communityIDArray.length - maxVisibleChips;

  return (
    <Collapse in={hasSelectedIDs}><Paper elevation={2}
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
        data-learn={i18nText("ui:m_0434328930d7c05b6485")}><Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>{/* Toggle and Label */}<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mr: 1 }}><Tooltip title={isFilterEnabled ? i18nText("ui:m_5145fe29da45514aafc1") : i18nText("ui:m_3063f452c50e9a7241af")}><FormControlLabel control={<Switch size="small" 
                    checked={isFilterEnabled} 
                    onChange={toggleFilterEnabled}
                    color="primary" />}
                label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>{isFilterEnabled ? (
                      <FilterListIcon color="primary" fontSize="small" />
                    ) : (
                      <FilterListOffIcon color="disabled" fontSize="small" />
                    )}<Typography variant="body2" 
                      color={isFilterEnabled ? 'primary' : 'text.disabled'} 
                      fontWeight="medium">
                      {i18nRichText("ui:m_219e340d1e77e370b827", { arg0: communityIDArray.length, arg1: !isFilterEnabled && i18nText("ui:m_4505558acd8f0c46a810") })}
                    </Typography></Box>}
                sx={{ m: 0 }} /></Tooltip></Box>{/* ID Chips */}{visibleChips.map((id) => (
            <Tooltip key={id} title={i18nText("ui:m_deeac3d6d7f0cd3b7623", { arg0: id })}><Chip label={id.length > 25 ? `${id.substring(0, 25)}...` : id}
                size="small"
                color={isFilterEnabled ? 'primary' : 'default'}
                variant={isFilterEnabled ? 'filled' : 'outlined'}
                onDelete={() => removeCommunityID(id)}
                deleteIcon={<ClearIcon fontSize="small" />}
                sx={{
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  maxWidth: { xs: 200, sm: 300 },
                  opacity: isFilterEnabled ? 1 : 0.6,
                  '& .MuiChip-label': {
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  },
                }} /></Tooltip>
          ))}{hiddenCount > 0 && (
            <Chip label={i18nText("ui:m_5000f686d6d8f94a73f9", { arg0: hiddenCount })}
              size="small"
              variant="outlined"
              onClick={() => setShowAllChips(true)} />
          )}{/* Clear All Button */}{communityIDArray.length > 1 && (
            <Tooltip title={i18nText("ui:m_10e58ce86328963d6cd1")}><Chip label={i18nText("ui:m_0cb3d73ec88de1474e7b")}
                size="small"
                variant="outlined"
                color="error"
                onClick={clearCommunityIDs}
                deleteIcon={<ClearIcon fontSize="small" />}
                onDelete={clearCommunityIDs}
                sx={{ ml: 1 }} /></Tooltip>
          )}</Box><Typography variant="caption" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' }, mt: 1 }}>{isFilterEnabled ? i18nText("ui:m_90f623e5b2cffc8f5535") : i18nText("ui:m_9e9f335be8386ba826f6")}</Typography></Paper></Collapse>
  );
}

export default CommunityIDFilterBar;

