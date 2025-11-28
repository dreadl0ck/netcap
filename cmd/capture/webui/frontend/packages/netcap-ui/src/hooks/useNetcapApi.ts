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
