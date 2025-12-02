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

import React, { ReactNode } from 'react';
import { Box, Card, CardContent, Grid, Typography } from '@mui/material';

export interface StatBoxProps {
  /** Icon to display */
  icon: ReactNode;
  /** Label text */
  label: string;
  /** Value to display */
  value: string | number;
  /** Optional click handler */
  onClick?: () => void;
  /** Whether this stat box is currently active/selected (shows border) */
  isActive?: boolean;
  /** Border color when active */
  activeColor?: 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info';
  /** Optional helper text shown when active */
  activeText?: string;
  /** Optional data-learn hint for learn mode */
  learnHint?: string;
}

/**
 * A compact stat box component for displaying statistics in table mode.
 * Supports click-to-filter behavior with visual feedback.
 */
export default function StatBox({
  icon,
  label,
  value,
  onClick,
  isActive = false,
  activeColor = 'primary',
  activeText,
  learnHint,
}: StatBoxProps) {
  const cardSx = onClick
    ? {
        cursor: 'pointer',
        border: isActive ? 2 : 0,
        borderColor: `${activeColor}.main`,
        transition: 'all 0.2s',
        '&:hover': {
          boxShadow: 3,
          transform: 'translateY(-2px)',
        },
      }
    : {};

  return (
    <Card sx={cardSx} onClick={onClick} data-learn={learnHint}>
      <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {icon}
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem', lineHeight: 1.2 }}>
              {label}
            </Typography>
            <Typography variant="h6" sx={{ fontSize: '1.1rem', fontWeight: 600, lineHeight: 1.3 }}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </Typography>
          </Box>
        </Box>
        {isActive && activeText && (
          <Typography variant="caption" color={`${activeColor}.main`} sx={{ display: 'block', mt: 0.5, fontSize: '0.7rem' }}>
            {activeText}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

export interface StatBoxGridProps {
  /** Child StatBox components */
  children: ReactNode;
}

/**
 * Grid wrapper for StatBox components.
 * Provides consistent spacing and responsive layout.
 */
export function StatBoxGrid({ children }: StatBoxGridProps) {
  return (
    <Grid container spacing={2} sx={{ mb: 2 }}>
      {React.Children.map(children, (child) => (
        <Grid item xs={12} sm={6} md={3}>
          {child}
        </Grid>
      ))}
    </Grid>
  );
}

