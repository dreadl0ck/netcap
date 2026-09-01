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

import { escapeHTML } from './html';

/**
 * Syntax highlighting for BPF (Berkeley Packet Filter) expressions
 * 
 * Supports tcpdump-style BPF syntax:
 * - Protocols (tcp, udp, icmp, ip, ip6, arp, etc.)
 * - Directions (src, dst, src or dst, src and dst)
 * - Types (host, net, port, portrange)
 * - Operators (and, or, not)
 * - Special keywords (less, greater, broadcast, multicast)
 */

export interface BPFToken {
  type: 'protocol' | 'direction' | 'keyword' | 'operator' | 'number' | 'ip' | 'string' | 'text';
  value: string;
  color: string;
}

// BPF protocols
const PROTOCOLS = new Set([
  'tcp', 'udp', 'icmp', 'icmp6', 'ip', 'ip6', 'arp', 'rarp', 'ether', 
  'wlan', 'fddi', 'tr', 'decnet', 'lat', 'sca', 'moprc', 'mopdl',
  'pppoes', 'pppoed', 'igmp', 'igrp', 'pim', 'ah', 'esp', 'vrrp',
  'atalk', 'aarp', 'iso', 'stp', 'ipx', 'netbeui', 'sctp', 'llc',
]);

// BPF keywords (directions, types, special)
const KEYWORDS = new Set([
  'host', 'net', 'port', 'portrange',
  'src', 'dst', 
  'less', 'greater',
  'broadcast', 'multicast',
  'proto', 'protochain',
  'gateway', 'vlan', 'mpls',
  'inbound', 'outbound',
  'len', 'type', 'subtype',
  'dir', 'reason', 'status',
  'ether', 'ip', 'ip6', 'arp', 'rarp', 'tcp', 'udp',
]);

// BPF logical operators
const OPERATORS = new Set(['and', 'or', 'not', '!', '&&', '||']);

/**
 * Tokenize and highlight a BPF filter expression
 */
export function highlightBPFExpression(expression: string): BPFToken[] {
  if (!expression) {
    return [];
  }

  const tokens: BPFToken[] = [];
  const words = expression.split(/(\s+|[()&|!])/);

  for (let word of words) {
    if (!word) continue;

    // Whitespace
    if (/^\s+$/.test(word)) {
      tokens.push({ type: 'text', value: word, color: 'inherit' });
      continue;
    }

    // Parentheses and logical operators (symbols)
    if (word === '(' || word === ')') {
      tokens.push({ type: 'operator', value: word, color: '#ffd700' });
      continue;
    }

    if (word === '&&' || word === '||' || word === '!') {
      tokens.push({ type: 'operator', value: word, color: '#d4d4d4' });
      continue;
    }

    const lowerWord = word.toLowerCase();

    // Protocols
    if (PROTOCOLS.has(lowerWord)) {
      tokens.push({ type: 'protocol', value: word, color: '#569cd6' }); // Blue
      continue;
    }

    // Operators (and, or, not)
    if (OPERATORS.has(lowerWord)) {
      tokens.push({ type: 'operator', value: word, color: '#d4d4d4' }); // Gray
      continue;
    }

    // Keywords
    if (KEYWORDS.has(lowerWord)) {
      tokens.push({ type: 'keyword', value: word, color: '#c586c0' }); // Purple
      continue;
    }

    // Numbers (ports, VLAN IDs, etc.)
    if (/^\d+$/.test(word)) {
      tokens.push({ type: 'number', value: word, color: '#b5cea8' }); // Light green
      continue;
    }

    // IP addresses (simple pattern)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(word)) {
      tokens.push({ type: 'ip', value: word, color: '#4ec9b0' }); // Teal
      continue;
    }

    // IPv6 addresses (simple pattern)
    if (/^[0-9a-fA-F:]+$/.test(word) && word.includes(':')) {
      tokens.push({ type: 'ip', value: word, color: '#4ec9b0' }); // Teal
      continue;
    }

    // MAC addresses
    if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(word)) {
      tokens.push({ type: 'string', value: word, color: '#ce9178' }); // Orange
      continue;
    }

    // CIDR notation or ranges
    if (word.includes('/') || word.includes('-')) {
      tokens.push({ type: 'string', value: word, color: '#ce9178' }); // Orange
      continue;
    }

    // Default: treat as text/identifier
    tokens.push({ type: 'text', value: word, color: '#9cdcfe' }); // Light blue
  }

  return tokens;
}

/**
 * Convert BPF tokens to HTML string with inline styles
 */
export function bpfTokensToHTML(tokens: BPFToken[]): string {
  return tokens
    .map(token => {
      if (token.type === 'text' && token.color === 'inherit') {
        return token.value;
      }
      return `<span style="color: ${token.color}">${escapeHTML(token.value)}</span>`;
    })
    .join('');
}


