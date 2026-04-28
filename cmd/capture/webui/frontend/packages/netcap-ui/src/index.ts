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
 * @dreadl0ck/netcap-ui - Netcap UI Component Library
 * 
 * A React component library for building network analysis interfaces.
 * These components can be used in any React application.
 *
 * @example
 * ```tsx
 * // Basic usage in any React app
 * import { NetcapProvider, Layout, useNetcapApi } from '@dreadl0ck/netcap-ui';
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
  ConnectionOverlay,
  CommunityIDChip,
  CommunityIDFilterBar,
} from './components';

export type {
  LayoutProps,
  FileSelectorHeaderProps,
  ConnectionOverlayProps,
} from './components';

// Contexts
export {
  LearnModeProvider,
  useLearnMode,
  CommunityIDFilterProvider,
  useCommunityIDFilter,
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
