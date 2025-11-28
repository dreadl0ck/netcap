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
 * Syntax highlighting for Filter Expression (expr-lang) syntax
 * 
 * Supports NETCAP filter expression syntax:
 * - Field names (DstPort, SrcIP, Timestamp, etc.)
 * - Operators (==, !=, <, >, <=, >=, &&, ||, !)
 * - Functions (InSubnet, IsPrivateIP, contains, etc.)
 * - String literals (single or double quoted)
 * - Numbers (integers and floats)
 * - Boolean literals (true, false)
 * - Parentheses and brackets
 */

export interface FilterToken {
  type: 'field' | 'operator' | 'function' | 'string' | 'number' | 'boolean' | 'paren' | 'text';
  value: string;
  color: string;
}

// Common field names in NETCAP audit records
const COMMON_FIELDS = new Set([
  'DstPort', 'SrcPort', 'SrcIP', 'DstIP', 'SrcMAC', 'DstMAC',
  'Timestamp', 'Protocol', 'Length', 'Payload',
  'SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG',
  'TTL', 'TOS', 'IHL', 'Version', 'Checksum',
  'WindowSize', 'SeqNum', 'AckNum',
  'Host', 'Method', 'URI', 'StatusCode', 'UserAgent',
  'ContentType', 'ContentLength',
  'Type', 'Code', 'ID', 'Seq',
]);

// Helper functions
const HELPER_FUNCTIONS = new Set([
  'InSubnet', 'IsPrivateIP', 'IsPublicIP', 
  'contains', 'startswith', 'endswith',
  'matches', 'len', 'lower', 'upper',
  'substr', 'replace',
]);

// Operators
const OPERATORS = new Set([
  '==', '!=', '<', '>', '<=', '>=',
  '&&', '||', '!',
  'and', 'or', 'not',
]);

/**
 * Tokenize and highlight a filter expression
 */
export function highlightFilterExpression(expression: string): FilterToken[] {
  if (!expression) {
    return [];
  }

  const tokens: FilterToken[] = [];
  let i = 0;

  while (i < expression.length) {
    let matched = false;

    // Skip whitespace
    if (/\s/.test(expression[i])) {
      tokens.push({ type: 'text', value: expression[i], color: 'inherit' });
      i++;
      continue;
    }

    // String literals (single or double quoted)
    if (expression[i] === '"' || expression[i] === "'") {
      const quote = expression[i];
      let j = i + 1;
      let escaped = false;
      
      while (j < expression.length) {
        if (escaped) {
          escaped = false;
          j++;
          continue;
        }
        if (expression[j] === '\\') {
          escaped = true;
          j++;
          continue;
        }
        if (expression[j] === quote) {
          j++;
          break;
        }
        j++;
      }
      
      tokens.push({ 
        type: 'string', 
        value: expression.substring(i, j), 
        color: '#ce9178' // Orange
      });
      i = j;
      matched = true;
    }

    // Numbers (integers and floats)
    if (!matched && /\d/.test(expression[i])) {
      const numMatch = expression.substring(i).match(/^\d+\.?\d*/);
      if (numMatch) {
        tokens.push({ 
          type: 'number', 
          value: numMatch[0], 
          color: '#b5cea8' // Light green
        });
        i += numMatch[0].length;
        matched = true;
      }
    }

    // Multi-character operators (must check before single-char operators)
    if (!matched) {
      const twoCharOp = expression.substring(i, i + 2);
      if (OPERATORS.has(twoCharOp)) {
        tokens.push({ 
          type: 'operator', 
          value: twoCharOp, 
          color: '#d4d4d4' // Gray
        });
        i += 2;
        matched = true;
      }
    }

    // Single-character operators and punctuation
    if (!matched && /[!<>=&|()]/.test(expression[i])) {
      if (expression[i] === '(' || expression[i] === ')') {
        tokens.push({ 
          type: 'paren', 
          value: expression[i], 
          color: '#ffd700' // Gold
        });
      } else {
        tokens.push({ 
          type: 'operator', 
          value: expression[i], 
          color: '#d4d4d4' // Gray
        });
      }
      i++;
      matched = true;
    }

    // Identifiers (field names, functions, keywords)
    if (!matched && /[a-zA-Z_]/.test(expression[i])) {
      const identMatch = expression.substring(i).match(/^[a-zA-Z_][a-zA-Z0-9_]*/);
      if (identMatch) {
        const ident = identMatch[0];
        
        // Check if it's a boolean literal
        if (ident === 'true' || ident === 'false') {
          tokens.push({ 
            type: 'boolean', 
            value: ident, 
            color: '#569cd6' // Blue
          });
        }
        // Check if it's an operator keyword
        else if (OPERATORS.has(ident.toLowerCase())) {
          tokens.push({ 
            type: 'operator', 
            value: ident, 
            color: '#d4d4d4' // Gray
          });
        }
        // Check if it's followed by '(' - it's a function call
        else if (i + ident.length < expression.length && expression[i + ident.length] === '(') {
          tokens.push({ 
            type: 'function', 
            value: ident, 
            color: '#dcdcaa' // Yellow
          });
        }
        // Check if it's a known helper function
        else if (HELPER_FUNCTIONS.has(ident)) {
          tokens.push({ 
            type: 'function', 
            value: ident, 
            color: '#dcdcaa' // Yellow
          });
        }
        // Check if it's a known field
        else if (COMMON_FIELDS.has(ident)) {
          tokens.push({ 
            type: 'field', 
            value: ident, 
            color: '#9cdcfe' // Light blue
          });
        }
        // Default: treat as field (could be a custom field)
        else {
          tokens.push({ 
            type: 'field', 
            value: ident, 
            color: '#9cdcfe' // Light blue
          });
        }
        
        i += ident.length;
        matched = true;
      }
    }

    // Default: plain text
    if (!matched) {
      tokens.push({ 
        type: 'text', 
        value: expression[i], 
        color: '#d4d4d4' // Light gray
      });
      i++;
    }
  }

  return tokens;
}

/**
 * Convert filter tokens to HTML string with inline styles
 */
export function filterTokensToHTML(tokens: FilterToken[]): string {
  return tokens
    .map(token => {
      if (token.type === 'text' && token.color === 'inherit') {
        return escapeHTML(token.value);
      }
      return `<span style="color: ${token.color}">${escapeHTML(token.value)}</span>`;
    })
    .join('');
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

