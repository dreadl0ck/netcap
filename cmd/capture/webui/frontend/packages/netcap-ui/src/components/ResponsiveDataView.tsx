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

import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import TablePagination from '@mui/material/TablePagination';
import Typography from '@mui/material/Typography';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import { useIsMobile } from '../hooks/useIsMobile';
import { mobileTablePaginationSx } from '../lib/mobileMixins';

export interface ResponsiveDataViewProps<T> {
  /** Data items for the current page */
  data: T[];
  /** Desktop table content (TableContainer with Table inside) */
  desktopTable: React.ReactNode;
  /** Mobile card renderer for each item */
  renderCard: (item: T, index: number) => React.ReactNode;
  /** Callback when a card is clicked on mobile */
  onCardClick?: (item: T) => void;
  /** Total item count (for pagination) */
  totalCount: number;
  /** Current page (0-indexed) */
  page: number;
  /** Rows per page */
  rowsPerPage: number;
  /** Page change handler */
  onPageChange: (event: unknown, newPage: number) => void;
  /** Rows-per-page change handler */
  onRowsPerPageChange?: (event: React.ChangeEvent<HTMLInputElement>) => void;
  /** Rows-per-page options */
  rowsPerPageOptions?: number[];
  /** Optional label for displayed rows */
  labelDisplayedRows?: (info: { from: number; to: number; count: number }) => string;
}

/**
 * Renders a desktop table or mobile card list based on viewport width.
 *
 * On md+ viewports: renders `desktopTable` as-is with standard TablePagination.
 * On xs/sm viewports: renders cards via `renderCard` with simplified pagination.
 */
export default function ResponsiveDataView<T>({
  data,
  desktopTable,
  renderCard,
  onCardClick,
  totalCount,
  page,
  rowsPerPage,
  onPageChange,
  onRowsPerPageChange,
  rowsPerPageOptions = [10, 25, 50, 100],
  labelDisplayedRows,
}: ResponsiveDataViewProps<T>) {
  const isMobile = useIsMobile();

  const totalPages = Math.ceil(totalCount / rowsPerPage);
  const from = totalCount === 0 ? 0 : page * rowsPerPage + 1;
  const to = Math.min((page + 1) * rowsPerPage, totalCount);

  if (isMobile) {
    return (
      <Box>
        <Stack spacing={1.5}>
          {data.map((item, index) => (
            <Box
              key={index}
              onClick={onCardClick ? () => onCardClick(item) : undefined}
              sx={onCardClick ? { cursor: 'pointer' } : undefined}
            >
              {renderCard(item, index)}
            </Box>
          ))}
        </Stack>
        {totalCount > 0 && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 1,
              py: 2,
            }}
          >
            <Button
              size="small"
              disabled={page === 0}
              onClick={(e) => onPageChange(e, page - 1)}
              startIcon={<NavigateBeforeIcon />}
            >
              Prev
            </Button>
            <Typography variant="body2" color="text.secondary">
              {from}-{to} of {totalCount.toLocaleString()}
            </Typography>
            <Button
              size="small"
              disabled={page >= totalPages - 1}
              onClick={(e) => onPageChange(e, page + 1)}
              endIcon={<NavigateNextIcon />}
            >
              Next
            </Button>
          </Box>
        )}
      </Box>
    );
  }

  return (
    <Box>
      {desktopTable}
      <TablePagination
        component="div"
        count={totalCount}
        page={page}
        onPageChange={onPageChange}
        rowsPerPage={rowsPerPage}
        onRowsPerPageChange={onRowsPerPageChange}
        rowsPerPageOptions={rowsPerPageOptions}
        sx={mobileTablePaginationSx}
        {...(labelDisplayedRows ? { labelDisplayedRows } : {})}
      />
    </Box>
  );
}
