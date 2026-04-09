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

/** Ensures 44px minimum touch target on mobile (WCAG 2.5.8). */
export const mobileTouchTarget = {
  minWidth: { xs: 44, sm: 'auto' },
  minHeight: { xs: 44, sm: 'auto' },
} as const;

/** Tighter table cell padding for mobile viewports. */
export const mobileTableCell = {
  px: { xs: 0.5, sm: 1, md: 2 },
  py: { xs: 0.5, sm: 1 },
} as const;

/** Responsive monospace font sizing for data views. */
export const mobileMonospaceFont = {
  fontSize: { xs: '11px', sm: '12px', md: '13px' },
} as const;

/** Horizontal scroll container with iOS momentum scrolling for tables. */
export const responsiveTableContainer = {
  overflowX: 'auto',
  WebkitOverflowScrolling: 'touch',
} as const;

/** Hides "Rows per page" label on mobile to save horizontal space. */
export const mobileTablePaginationSx = {
  '& .MuiTablePagination-selectLabel': {
    display: { xs: 'none', sm: 'block' },
  },
  '& .MuiTablePagination-displayedRows': {
    fontSize: { xs: '0.75rem', sm: '0.875rem' },
  },
  '& .MuiTablePagination-select': {
    fontSize: { xs: '0.75rem', sm: '0.875rem' },
  },
} as const;
