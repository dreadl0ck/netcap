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

