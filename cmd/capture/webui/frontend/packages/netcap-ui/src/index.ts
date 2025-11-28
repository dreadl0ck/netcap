/**
 * @netcap/ui - Netcap UI Component Library
 * 
 * A React component library for building network analysis interfaces.
 * These components can be used in any React application, not just Next.js.
 * 
 * @example
 * ```tsx
 * // Basic usage in any React app
 * import { NetcapProvider, Layout, useNetcapApi } from '@netcap/ui';
 * 
 * function App() {
 *   return (
 *     <NetcapProvider config={{
 *       backendUrl: 'http://localhost:8080',
 *       router: myRouterAdapter,
 *       Link: MyLinkComponent,
 *     }}>
 *       <Layout title="My App">
 *         <MyContent />
 *       </Layout>
 *     </NetcapProvider>
 *   );
 * }
 * ```
 * 
 * @example
 * ```tsx
 * // Usage in Next.js with the adapter
 * import { NextjsNetcapProvider } from '@netcap/ui/adapters/nextjs';
 * import { Layout } from '@netcap/ui/components';
 * 
 * function MyPage() {
 *   return (
 *     <Layout title="My Page">
 *       <MyContent />
 *     </Layout>
 *   );
 * }
 * 
 * export default function App({ Component, pageProps }) {
 *   return (
 *     <NextjsNetcapProvider backendUrl="http://localhost:8080">
 *       <Component {...pageProps} />
 *     </NextjsNetcapProvider>
 *   );
 * }
 * ```
 */

// Providers
export {
  NetcapProvider,
  useNetcapConfig,
  useBackendUrl,
  useApiBaseUrl,
  useNetcapLink,
  useNetcapDebug,
} from './providers';

export type {
  NetcapConfig,
  NetcapProviderProps,
  RouterAdapter,
  LinkProps,
  LinkComponent,
} from './providers';

// Hooks
export {
  useNetcapRouter,
  useNetcapApi,
} from './hooks';

export type {
  NetcapRouter,
} from './hooks';

// Components
export {
  Layout,
  NetcapLink,
  FileSelectorHeader,
  LearnModeToggle,
  LearnModeOverlay,
} from './components';

export type {
  LayoutProps,
  FileSelectorHeaderProps,
} from './components';

// Contexts
export {
  LearnModeProvider,
  useLearnMode,
} from './contexts';

// Library utilities - re-export everything from lib
export {
  api,
  createApi,
  getBackendUrl,
  formatBytes,
  formatTimestamp,
  formatDuration,
  highlightFilterExpression,
  highlightBPFExpression,
  highlightRegexPattern,
} from './lib';

// Re-export all types from lib (simplified using export type *)
export type * from './lib';
