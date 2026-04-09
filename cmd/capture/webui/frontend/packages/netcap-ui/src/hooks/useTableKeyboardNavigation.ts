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

import { useEffect, useCallback } from 'react';

/**
 * Hook to enable keyboard navigation (UP/DOWN arrows) for table detail views.
 * When a row detail is expanded, pressing UP/DOWN will navigate to the
 * previous/next row's detail view for quick skimming.
 * 
 * @param expandedRow - The currently expanded row key, or null if none expanded
 * @param rowKeys - Array of all row keys in display order
 * @param setExpandedRow - Setter function to change the expanded row
 */
export function useTableKeyboardNavigation(
  expandedRow: string | null,
  rowKeys: string[],
  setExpandedRow: (key: string | null) => void
) {
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    // Only handle navigation when a row is expanded
    if (!expandedRow || rowKeys.length === 0) return;

    // Don't interfere with input fields
    const target = event.target as HTMLElement;
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
      return;
    }

    const currentIndex = rowKeys.indexOf(expandedRow);
    if (currentIndex === -1) return;

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      const newIndex = currentIndex - 1;
      if (newIndex >= 0) {
        setExpandedRow(rowKeys[newIndex]);
        // Scroll the new row into view
        requestAnimationFrame(() => {
          const newRowElement = document.querySelector(`[data-row-key="${rowKeys[newIndex]}"]`);
          if (newRowElement) {
            newRowElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        });
      }
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      const newIndex = currentIndex + 1;
      if (newIndex < rowKeys.length) {
        setExpandedRow(rowKeys[newIndex]);
        // Scroll the new row into view
        requestAnimationFrame(() => {
          const newRowElement = document.querySelector(`[data-row-key="${rowKeys[newIndex]}"]`);
          if (newRowElement) {
            newRowElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        });
      }
    } else if (event.key === 'Escape') {
      event.preventDefault();
      setExpandedRow(null);
    }
  }, [expandedRow, rowKeys, setExpandedRow]);

  useEffect(() => {
    if (expandedRow) {
      document.addEventListener('keydown', handleKeyDown);
      return () => {
        document.removeEventListener('keydown', handleKeyDown);
      };
    }
  }, [expandedRow, handleKeyDown]);
}

