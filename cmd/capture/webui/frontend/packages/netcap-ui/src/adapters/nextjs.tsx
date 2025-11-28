/**
 * Next.js Adapter for Netcap UI
 * 
 * This adapter provides seamless integration with Next.js applications.
 * It automatically configures the NetcapProvider with Next.js's router and Link.
 * 
 * @example
 * ```tsx
 * // In _app.tsx
 * import { NextjsNetcapProvider } from '@netcap/ui/adapters/nextjs';
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
import { useRouter } from 'next/router';
import NextLink from 'next/link';
import { NetcapProvider, NetcapConfig, LinkProps } from '../providers/NetcapProvider';
import { LearnModeProvider } from '../contexts/LearnModeContext';

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

