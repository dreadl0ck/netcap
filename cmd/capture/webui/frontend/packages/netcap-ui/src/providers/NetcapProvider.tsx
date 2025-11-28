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

import React, { createContext, useContext, ReactNode, useMemo } from 'react';

/**
 * Check if we're running on the server (SSR)
 */
const isSSR = typeof window === 'undefined';

/**
 * Router adapter interface - abstracts routing functionality
 * Can be implemented by Next.js, React Router, or any other router
 */
export interface RouterAdapter {
  /** Current pathname */
  pathname: string;
  /** Query parameters */
  query: Record<string, string | string[] | undefined>;
  /** Whether the router is ready (hydrated) */
  isReady: boolean;
  /** Navigate to a new path */
  push: (path: string) => void | Promise<boolean>;
  /** Replace current path */
  replace?: (path: string) => void | Promise<boolean>;
}

/**
 * Link component props - for creating navigation links
 */
export interface LinkProps {
  href: string;
  children: ReactNode;
  passHref?: boolean;
  style?: React.CSSProperties;
  className?: string;
  target?: string;
  rel?: string;
  title?: string;
  onClick?: (e: React.MouseEvent) => void;
}

/**
 * Link component type - can be next/link or react-router Link
 */
export type LinkComponent = React.ComponentType<LinkProps>;

/**
 * Partial API type - allows overriding specific API methods
 */
export type PartialApi = Partial<typeof import('../lib/api').api>;

/**
 * Main configuration for NetcapProvider
 */
export interface NetcapConfig {
  /** Backend API URL (e.g., 'http://localhost:8080') */
  backendUrl: string;
  
  /** Router adapter for navigation */
  router: RouterAdapter;
  
  /** Link component for navigation links */
  Link: LinkComponent;
  
  /** Optional: Custom API implementation (partial overrides) */
  api?: PartialApi;
  
  /** Optional: Custom fetch implementation */
  fetch?: typeof fetch;
  
  /** Optional: Enable debug logging */
  debug?: boolean;
}

/**
 * Internal context value with computed properties
 */
interface NetcapContextValue extends NetcapConfig {
  /** Full API base URL */
  apiBaseUrl: string;
  /** Whether we're in SSR mode (no real provider available) */
  isSSR: boolean;
}

/**
 * Fallback router for SSR - does nothing but prevents errors during prerendering
 */
const ssrFallbackRouter: RouterAdapter = {
  pathname: '/',
  query: {},
  isReady: false,
  push: () => Promise.resolve(true),
  replace: () => Promise.resolve(true),
};

/**
 * Fallback Link component for SSR
 */
const SSRFallbackLink: LinkComponent = ({ href, children, ...props }) => (
  <a href={href} {...props}>{children}</a>
);

/**
 * SSR fallback context value - used during static site generation
 * This prevents "useNetcapConfig must be used within a NetcapProvider" errors during SSG
 */
const ssrFallbackValue: NetcapContextValue = {
  backendUrl: '',
  apiBaseUrl: '/api',
  router: ssrFallbackRouter,
  Link: SSRFallbackLink,
  debug: false,
  isSSR: true,
};

const NetcapContext = createContext<NetcapContextValue | null>(null);

export interface NetcapProviderProps {
  children: ReactNode;
  config: NetcapConfig;
}

/**
 * NetcapProvider - Provides configuration context for all Netcap UI components
 * 
 * @example
 * ```tsx
 * // In a Next.js app
 * import { NetcapProvider } from '@dreadl0ck/netcap-ui/providers';
 * import { useRouter } from 'next/router';
 * import Link from 'next/link';
 * 
 * function App({ children }) {
 *   const router = useRouter();
 *   return (
 *     <NetcapProvider config={{
 *       backendUrl: 'http://localhost:8080',
 *       router: {
 *         pathname: router.pathname,
 *         query: router.query,
 *         isReady: router.isReady,
 *         push: router.push,
 *       },
 *       Link,
 *     }}>
 *       {children}
 *     </NetcapProvider>
 *   );
 * }
 * ```
 * 
 * @example
 * ```tsx
 * // In a React Router app
 * import { NetcapProvider } from '@dreadl0ck/netcap-ui/providers';
 * import { useNavigate, useLocation, useSearchParams, Link } from 'react-router-dom';
 * 
 * function App({ children }) {
 *   const navigate = useNavigate();
 *   const location = useLocation();
 *   const [searchParams] = useSearchParams();
 *   
 *   return (
 *     <NetcapProvider config={{
 *       backendUrl: 'https://my-netcap-server.com',
 *       router: {
 *         pathname: location.pathname,
 *         query: Object.fromEntries(searchParams),
 *         isReady: true,
 *         push: navigate,
 *       },
 *       Link: ({ href, children, ...props }) => (
 *         <Link to={href} {...props}>{children}</Link>
 *       ),
 *     }}>
 *       {children}
 *     </NetcapProvider>
 *   );
 * }
 * ```
 */
export function NetcapProvider({ children, config }: NetcapProviderProps) {
  const value = useMemo<NetcapContextValue>(() => ({
    ...config,
    apiBaseUrl: `${config.backendUrl}/api`,
    isSSR: false,
  }), [config]);

  return (
    <NetcapContext.Provider value={value}>
      {children}
    </NetcapContext.Provider>
  );
}

/**
 * Hook to access the full Netcap configuration
 * 
 * During SSR (static site generation), returns a fallback value to prevent errors.
 * The app will hydrate properly on the client with real values.
 */
export function useNetcapConfig(): NetcapContextValue {
  const config = useContext(NetcapContext);
  
  // During SSR, return fallback to prevent errors during static generation
  // The app is always embedded, so SSR output is just a placeholder
  if (!config) {
    if (isSSR) {
      return ssrFallbackValue;
    }
    throw new Error(
      'useNetcapConfig must be used within a NetcapProvider. ' +
      'Wrap your app with <NetcapProvider config={...}>.'
    );
  }
  return config;
}

/**
 * Hook to get just the backend URL
 */
export function useBackendUrl(): string {
  const { backendUrl } = useNetcapConfig();
  return backendUrl;
}

/**
 * Hook to get the API base URL
 */
export function useApiBaseUrl(): string {
  const { apiBaseUrl } = useNetcapConfig();
  return apiBaseUrl;
}

/**
 * Hook to get the Link component
 */
export function useNetcapLink(): LinkComponent {
  const { Link } = useNetcapConfig();
  return Link;
}

/**
 * Hook to check if debug mode is enabled
 */
export function useNetcapDebug(): boolean {
  const { debug } = useNetcapConfig();
  return debug ?? false;
}

/**
 * Hook to check if we're running in SSR mode
 * Components can use this to conditionally skip data fetching during SSR
 * 
 * @example
 * ```tsx
 * function MyComponent() {
 *   const isSSR = useIsSSR();
 *   const api = useNetcapApi();
 *   // Skip fetching during SSR by passing null as key
 *   const { data } = useSWR(isSSR ? null : 'status', () => api.getStatus());
 * }
 * ```
 */
export function useIsSSR(): boolean {
  const config = useNetcapConfig();
  return config.isSSR;
}

export default NetcapProvider;

