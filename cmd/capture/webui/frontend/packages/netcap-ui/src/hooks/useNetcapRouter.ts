import { useCallback, useMemo } from 'react';
import { useNetcapConfig, RouterAdapter } from '../providers/NetcapProvider';

/**
 * Extended router interface with additional convenience methods
 */
export interface NetcapRouter extends RouterAdapter {
  /** Navigate to a path with optional query parameters */
  navigateTo: (path: string, query?: Record<string, string>) => void;
  
  /** Get a query parameter value as string */
  getQueryParam: (key: string) => string | undefined;
  
  /** Get all query parameters as a flat object */
  getQueryParams: () => Record<string, string>;
  
  /** Check if a path is currently active */
  isActive: (path: string) => boolean;
}

/**
 * Hook to access router functionality - replaces useRouter from next/router
 * 
 * @example
 * ```tsx
 * function MyComponent() {
 *   const router = useNetcapRouter();
 *   
 *   // Navigate programmatically
 *   const handleClick = () => {
 *     router.push('/hosts');
 *   };
 *   
 *   // Get query params
 *   const searchQuery = router.getQueryParam('search');
 *   
 *   // Check if path is active
 *   const isHostsActive = router.isActive('/hosts');
 *   
 *   return <div>...</div>;
 * }
 * ```
 */
export function useNetcapRouter(): NetcapRouter {
  const { router } = useNetcapConfig();

  const navigateTo = useCallback((path: string, query?: Record<string, string>) => {
    if (query && Object.keys(query).length > 0) {
      const params = new URLSearchParams(query);
      router.push(`${path}?${params.toString()}`);
    } else {
      router.push(path);
    }
  }, [router]);

  const getQueryParam = useCallback((key: string): string | undefined => {
    const value = router.query[key];
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }, [router.query]);

  const getQueryParams = useCallback((): Record<string, string> => {
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(router.query)) {
      if (value !== undefined) {
        result[key] = Array.isArray(value) ? value[0] : value;
      }
    }
    return result;
  }, [router.query]);

  const isActive = useCallback((path: string): boolean => {
    if (path === '/') {
      return router.pathname === '/';
    }
    // Exact match for specific paths like /rules vs /rulesets
    if (path === '/rules') {
      return router.pathname === '/rules';
    }
    return router.pathname.startsWith(path);
  }, [router.pathname]);

  return useMemo(() => ({
    ...router,
    navigateTo,
    getQueryParam,
    getQueryParams,
    isActive,
  }), [router, navigateTo, getQueryParam, getQueryParams, isActive]);
}

export default useNetcapRouter;

