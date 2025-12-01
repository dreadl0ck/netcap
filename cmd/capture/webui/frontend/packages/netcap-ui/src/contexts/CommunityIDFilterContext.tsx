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

import { createContext, useContext, useState, useMemo, useCallback, ReactNode } from 'react';

/**
 * Check if we're running on the server (SSR)
 */
const isSSR = typeof window === 'undefined';

interface CommunityIDFilterContextType {
  /** Set of selected Community IDs for filtering */
  selectedCommunityIDs: Set<string>;
  /** Add a Community ID to the filter */
  addCommunityID: (id: string) => void;
  /** Remove a Community ID from the filter */
  removeCommunityID: (id: string) => void;
  /** Toggle a Community ID in the filter */
  toggleCommunityID: (id: string) => void;
  /** Clear all selected Community IDs */
  clearCommunityIDs: () => void;
  /** Check if a Community ID is selected */
  isCommunityIDSelected: (id: string) => boolean;
  /** Check if filter is active (IDs selected AND enabled) */
  isFilterActive: boolean;
  /** Number of selected Community IDs */
  filterCount: number;
  /** Whether the filter is enabled (can be toggled on/off without clearing IDs) */
  isFilterEnabled: boolean;
  /** Toggle the filter on/off */
  toggleFilterEnabled: () => void;
  /** Set the filter enabled state */
  setFilterEnabled: (enabled: boolean) => void;
}

/**
 * SSR fallback value for CommunityID filter context
 */
const ssrFallbackValue: CommunityIDFilterContextType = {
  selectedCommunityIDs: new Set(),
  addCommunityID: () => {},
  removeCommunityID: () => {},
  toggleCommunityID: () => {},
  clearCommunityIDs: () => {},
  isCommunityIDSelected: () => false,
  isFilterActive: false,
  filterCount: 0,
  isFilterEnabled: true,
  toggleFilterEnabled: () => {},
  setFilterEnabled: () => {},
};

const CommunityIDFilterContext = createContext<CommunityIDFilterContextType | undefined>(undefined);

export function CommunityIDFilterProvider({ children }: { children: ReactNode }) {
  const [selectedCommunityIDs, setSelectedCommunityIDs] = useState<Set<string>>(new Set());
  const [isFilterEnabled, setIsFilterEnabled] = useState<boolean>(true);

  const addCommunityID = useCallback((id: string) => {
    setSelectedCommunityIDs(prev => {
      const newSet = new Set(prev);
      newSet.add(id);
      return newSet;
    });
    // Auto-enable filter when adding an ID
    setIsFilterEnabled(true);
  }, []);

  const removeCommunityID = useCallback((id: string) => {
    setSelectedCommunityIDs(prev => {
      const newSet = new Set(prev);
      newSet.delete(id);
      return newSet;
    });
  }, []);

  const toggleCommunityID = useCallback((id: string) => {
    setSelectedCommunityIDs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
        // Auto-enable filter when adding an ID
        setIsFilterEnabled(true);
      }
      return newSet;
    });
  }, []);

  const clearCommunityIDs = useCallback(() => {
    setSelectedCommunityIDs(new Set());
  }, []);

  const isCommunityIDSelected = useCallback((id: string) => {
    return selectedCommunityIDs.has(id);
  }, [selectedCommunityIDs]);

  const toggleFilterEnabled = useCallback(() => {
    setIsFilterEnabled(prev => !prev);
  }, []);

  const setFilterEnabled = useCallback((enabled: boolean) => {
    setIsFilterEnabled(enabled);
  }, []);

  // Filter is active only when there are IDs AND filter is enabled
  const isFilterActive = selectedCommunityIDs.size > 0 && isFilterEnabled;
  const filterCount = selectedCommunityIDs.size;

  const value = useMemo(
    () => ({
      selectedCommunityIDs,
      addCommunityID,
      removeCommunityID,
      toggleCommunityID,
      clearCommunityIDs,
      isCommunityIDSelected,
      isFilterActive,
      filterCount,
      isFilterEnabled,
      toggleFilterEnabled,
      setFilterEnabled,
    }),
    [
      selectedCommunityIDs,
      addCommunityID,
      removeCommunityID,
      toggleCommunityID,
      clearCommunityIDs,
      isCommunityIDSelected,
      isFilterActive,
      filterCount,
      isFilterEnabled,
      toggleFilterEnabled,
      setFilterEnabled,
    ]
  );

  return (
    <CommunityIDFilterContext.Provider value={value}>
      {children}
    </CommunityIDFilterContext.Provider>
  );
}

export function useCommunityIDFilter() {
  const context = useContext(CommunityIDFilterContext);
  
  // During SSR, return fallback to prevent errors during static generation
  if (context === undefined) {
    if (isSSR) {
      return ssrFallbackValue;
    }
    throw new Error('useCommunityIDFilter must be used within a CommunityIDFilterProvider');
  }
  return context;
}

