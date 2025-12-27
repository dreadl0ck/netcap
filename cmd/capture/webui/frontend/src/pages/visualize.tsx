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

// Visualize page wrapper - imports from @dreadl0ck/netcap-ui package
// Dynamic import with ssr: false to prevent prerendering issues with React context
import dynamic from 'next/dynamic';

const VisualizePage = dynamic(
  () => import('@dreadl0ck/netcap-ui/pages').then(mod => mod.VisualizePage),
  { ssr: false }
);

export default function Visualize() {
  return <VisualizePage />;
}
