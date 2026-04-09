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

import { IconButton, Tooltip, Box } from '@mui/material';
import SchoolIcon from '@mui/icons-material/School';
import { useLearnMode } from '../contexts/LearnModeContext';

interface LearnModeToggleProps {
  size?: 'small' | 'medium' | 'large';
}

export function LearnModeToggle({ size }: LearnModeToggleProps) {
  const { isLearnModeActive, toggleLearnMode } = useLearnMode();
  const fontSize = size === 'small' ? 'small' : undefined;

  return (
    <Tooltip title={isLearnModeActive ? 'Exit Learn Mode' : 'Enter Learn Mode'}>
      <Box sx={{ position: 'relative' }}>
        <IconButton
          color="inherit"
          size={size}
          onClick={toggleLearnMode}
          sx={{
            color: isLearnModeActive ? '#00bcd4' : 'inherit',
            backgroundColor: isLearnModeActive ? 'rgba(0, 188, 212, 0.1)' : 'transparent',
            '&:hover': {
              backgroundColor: isLearnModeActive ? 'rgba(0, 188, 212, 0.2)' : 'rgba(255, 255, 255, 0.1)',
            },
            transition: 'all 0.3s',
          }}
        >
          <SchoolIcon fontSize={fontSize} />
        </IconButton>
        {isLearnModeActive && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              right: 0,
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: '#00bcd4',
              animation: 'pulse 2s infinite',
              '@keyframes pulse': {
                '0%, 100%': {
                  opacity: 1,
                },
                '50%': {
                  opacity: 0.5,
                },
              },
            }}
          />
        )}
      </Box>
    </Tooltip>
  );
}

export default LearnModeToggle;


