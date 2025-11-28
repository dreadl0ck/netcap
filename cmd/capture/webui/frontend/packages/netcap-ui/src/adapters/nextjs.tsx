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
 * Next.js Adapter for Netcap UI
 * 
 * This adapter provides seamless integration with Next.js applications.
 * It automatically configures the NetcapProvider with Next.js's router and Link.
 * 
 * @example
 * ```tsx
 * // In _app.tsx
 * import { NextjsNetcapProvider } from '@dreadl0ck/netcap-ui/adapters/nextjs';
 * import type { AppProps } from 'next/app';
 * 
 * export default function App({ Component, pageProps }: AppProps) {
 *   return (
 *     <NextjsNetcapProvider backendUrl="http://localhost:8080">
 *       <Component {...pageProps} />
 *     </NextjsNetcapProvider>
 *   );
 * }
 * ```
 */

import React, { ReactNode, useMemo } from 'react';
// Use .js extensions for ESM compatibility
import { useRouter } from 'next/router.js';
import NextLink from 'next/link.js';
import { NetcapProvider, NetcapConfig, LinkProps } from '../providers/NetcapProvider.js';
import { LearnModeProvider } from '../contexts/LearnModeContext.js';

export interface NextjsNetcapProviderProps {
  children: ReactNode;
  /** Backend URL for the Netcap API */
  backendUrl: string;
  /** Enable debug mode */
  debug?: boolean;
  /** Include LearnModeProvider (default: true) */
  includeLearnMode?: boolean;
}

/**
 * Wrapper component for Next.js Link that adapts to the Netcap Link interface
 */
function NextLinkAdapter({ href, children, passHref, ...props }: LinkProps) {
  return (
    <NextLink href={href} passHref={passHref} {...props}>
      {children}
    </NextLink>
  );
}

/**
 * NetcapProvider configured for Next.js applications
 * 
 * This provider automatically integrates with Next.js's router and Link components,
 * making it easy to use Netcap UI components in a Next.js app.
 * 
 * Also includes LearnModeProvider by default for the learn mode feature.
 */
export function NextjsNetcapProvider({ 
  children, 
  backendUrl,
  debug = false,
  includeLearnMode = true,
}: NextjsNetcapProviderProps) {
  const router = useRouter();

  const config = useMemo<NetcapConfig>(() => ({
    backendUrl,
    debug,
    router: {
      pathname: router.pathname,
      query: router.query as Record<string, string | string[] | undefined>,
      isReady: router.isReady,
      push: (path: string) => router.push(path),
      replace: (path: string) => router.replace(path),
    },
    Link: NextLinkAdapter,
  }), [backendUrl, debug, router.pathname, router.query, router.isReady, router.push, router.replace]);

  const content = includeLearnMode ? (
    <LearnModeProvider>{children}</LearnModeProvider>
  ) : children;

  return (
    <NetcapProvider config={config}>
      {content}
    </NetcapProvider>
  );
}

export default NextjsNetcapProvider;

