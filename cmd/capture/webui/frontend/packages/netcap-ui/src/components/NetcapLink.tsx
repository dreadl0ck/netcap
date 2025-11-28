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

import React from 'react';
import { useNetcapLink, LinkProps } from '../providers/NetcapProvider';

/**
 * NetcapLink - A wrapper component that uses the Link component from the provider
 * 
 * This component abstracts the underlying navigation library (Next.js Link, React Router Link, etc.)
 * and uses whatever Link component was provided to NetcapProvider.
 * 
 * @example
 * ```tsx
 * // Use just like you would use next/link
 * <NetcapLink href="/hosts">View Hosts</NetcapLink>
 * 
 * // With additional props
 * <NetcapLink href="/alerts" style={{ color: 'red' }}>
 *   View Alerts
 * </NetcapLink>
 * ```
 */
export function NetcapLink({ href, children, ...props }: LinkProps) {
  const Link = useNetcapLink();
  
  return (
    <Link href={href} {...props}>
      {children}
    </Link>
  );
}

export default NetcapLink;


