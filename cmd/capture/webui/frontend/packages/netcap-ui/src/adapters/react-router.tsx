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

/**
 * React Router Adapter for Netcap UI
 *
 * This adapter provides seamless integration with React Router v7 applications.
 * It automatically configures the NetcapProvider with React Router's navigation.
 *
 * @example
 * ```tsx
 * // In main.tsx
 * import { BrowserRouter } from 'react-router';
 * import { ReactRouterNetcapProvider } from '@dreadl0ck/netcap-ui/adapters/react-router';
 *
 * function App() {
 *   return (
 *     <BrowserRouter>
 *       <ReactRouterNetcapProvider backendUrl="http://localhost:8080">
 *         <AppRoutes />
 *       </ReactRouterNetcapProvider>
 *     </BrowserRouter>
 *   );
 * }
 * ```
 */

import React, { ReactNode, useMemo } from 'react';
import { useNavigate, useLocation, useSearchParams, Link as RRLink } from 'react-router';
import type { LinkProps as RRLinkProps } from 'react-router';
import { NetcapProvider, NetcapConfig, LinkProps } from '../providers/NetcapProvider.js';
import { LearnModeProvider } from '../contexts/LearnModeContext.js';
import { CommunityIDFilterProvider } from '../contexts/CommunityIDFilterContext.js';

export interface ReactRouterNetcapProviderProps {
  children: ReactNode;
  /** Backend URL for the Netcap API */
  backendUrl: string;
  /** Enable debug mode */
  debug?: boolean;
  /** Include LearnModeProvider (default: true) */
  includeLearnMode?: boolean;
}

/**
 * Wrapper component for React Router Link that adapts to the Netcap Link interface
 */
function ReactRouterLinkAdapter({ href, children, passHref, ...props }: LinkProps) {
  return (
    <RRLink to={href} {...(props as Omit<RRLinkProps, 'to'>)}>
      {children}
    </RRLink>
  );
}

/**
 * NetcapProvider configured for React Router applications
 *
 * This provider automatically integrates with React Router's navigation,
 * making it easy to use Netcap UI components in a Vite + React Router app.
 *
 * Also includes LearnModeProvider by default for the learn mode feature.
 */
export function ReactRouterNetcapProvider({
  children,
  backendUrl,
  debug = false,
  includeLearnMode = true,
}: ReactRouterNetcapProviderProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const config = useMemo<NetcapConfig>(() => ({
    backendUrl,
    debug,
    router: {
      pathname: location.pathname,
      query: Object.fromEntries(searchParams),
      isReady: true, // Always ready in SPA — no hydration step
      push: (path: string) => { navigate(path); },
      replace: (path: string) => { navigate(path, { replace: true }); },
    },
    Link: ReactRouterLinkAdapter,
  }), [backendUrl, debug, location.pathname, searchParams, navigate]);

  const content = includeLearnMode ? (
    <LearnModeProvider>
      <CommunityIDFilterProvider>{children}</CommunityIDFilterProvider>
    </LearnModeProvider>
  ) : (
    <CommunityIDFilterProvider>{children}</CommunityIDFilterProvider>
  );

  return (
    <NetcapProvider config={config}>
      {content}
    </NetcapProvider>
  );
}

export default ReactRouterNetcapProvider;
