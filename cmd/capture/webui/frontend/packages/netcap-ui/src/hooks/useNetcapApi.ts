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

import { useMemo } from 'react';
import { useNetcapConfig } from '../providers/NetcapProvider';
import { createApi, type NetcapApiClient } from '../lib/api';

/**
 * Hook to get a configured API client
 * 
 * Returns an API client that uses the backendUrl configured in NetcapProvider.
 * This ensures all API calls go to the correct backend server.
 * 
 * @example
 * ```tsx
 * function MyComponent() {
 *   const api = useNetcapApi();
 *   
 *   const { data } = useSWR('status', () => api.getStatus());
 *   
 *   return <div>{data?.isProcessing ? 'Processing...' : 'Idle'}</div>;
 * }
 * ```
 */
export function useNetcapApi(): NetcapApiClient {
  const { backendUrl, api: customApi } = useNetcapConfig();

  // Create an API client with the configured backend URL
  // Memoize to prevent recreating on every render
  return useMemo(() => {
    const baseApi = createApi(backendUrl);
    
    // If the provider has custom API overrides, merge them
    if (customApi) {
      return { ...baseApi, ...customApi } as NetcapApiClient;
    }
    
    return baseApi;
  }, [backendUrl, customApi]);
}

export default useNetcapApi;
