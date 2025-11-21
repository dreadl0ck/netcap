/**
 * Syntax highlighting for NETCAP filter expressions (expr-lang)
 * 
 * Supports:
 * - Field names (DstPort, SrcIP, etc.)
 * - Operators (==, !=, <, >, <=, >=, &&, ||, !)
 * - Functions (contains, startsWith, InSubnet, etc.)
 * - String literals ('...' or "...")
 * - Numbers (integers and floats)
 * - Boolean literals (true, false)
 * - Parentheses and brackets
 */

import React from 'react';

export interface HighlightedToken {
  type: 'field' | 'operator' | 'function' | 'string' | 'number' | 'boolean' | 'parenthesis' | 'bracket' | 'comma' | 'text';
  value: string;
  color: string;
}

// Known field names (common ones across most audit records)
const COMMON_FIELDS = new Set([
  'Timestamp', 'SrcIP', 'DstIP', 'SrcPort', 'DstPort', 'Protocol', 'Length', 'Size',
  'SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG', 'ECE', 'CWR', 'NS',
  'SeqNum', 'AckNum', 'Window', 'Checksum', 'Urgent',
  'SrcMAC', 'DstMAC', 'EthernetType',
  'Version', 'IHL', 'TOS', 'ID', 'Flags', 'FragOffset', 'TTL',
  'PayloadEntropy', 'PayloadSize',
  'FlowID', 'Duration', 'NumPackets', 'NumBytes',
  'Application', 'Category', 'Risk',
  'Domain', 'Query', 'ResponseCode', 'Answers',
  'Method', 'Host', 'UserAgent', 'StatusCode', 'ContentType',
  'ServerName', 'JA3', 'JA3S',
]);

// Known helper functions
const HELPER_FUNCTIONS = new Set([
  'InSubnet', 'IsPrivateIP', 'IsPublicIP', 'ParsePort', 'PortInRange',
  'TimeInRange', 'DurationSince', 'FormatTime',
  'ContainsAny', 'MatchesPattern',
  'contains', 'startsWith', 'endsWith', 'matches',
  'len', 'lower', 'upper', 'trim',
]);

// Operators (in order of precedence for matching)
const OPERATORS = [
  '==', '!=', '<=', '>=', '&&', '||',
  '<', '>', '!', '+', '-', '*', '/', '%',
  '=', 'in', 'not',
];

// Boolean literals
const BOOLEAN_LITERALS = new Set(['true', 'false']);

/**
 * Tokenize and highlight a filter expression
 */
export function highlightFilterExpression(expression: string): HighlightedToken[] {
  if (!expression) {
    return [];
  }

  const tokens: HighlightedToken[] = [];
  let i = 0;

  while (i < expression.length) {
    const char = expression[i];

    // Skip whitespace
    if (/\s/.test(char)) {
      tokens.push({ type: 'text', value: char, color: 'inherit' });
      i++;
      continue;
    }

    // String literals (single or double quotes)
    if (char === "'" || char === '"') {
      const quote = char;
      let str = quote;
      i++;
      while (i < expression.length) {
        const c = expression[i];
        str += c;
        if (c === quote && expression[i - 1] !== '\\') {
          i++;
          break;
        }
        i++;
      }
      tokens.push({ type: 'string', value: str, color: '#ce9178' }); // String color
      continue;
    }

    // Numbers (integers and floats)
    if (/\d/.test(char)) {
      let num = '';
      while (i < expression.length && /[\d.]/.test(expression[i])) {
        num += expression[i];
        i++;
      }
      tokens.push({ type: 'number', value: num, color: '#b5cea8' }); // Number color
      continue;
    }

    // Operators (multi-character first)
    let foundOperator = false;
    for (const op of OPERATORS) {
      if (expression.substr(i, op.length) === op) {
        tokens.push({ type: 'operator', value: op, color: '#d4d4d4' }); // Operator color
        i += op.length;
        foundOperator = true;
        break;
      }
    }
    if (foundOperator) {
      continue;
    }

    // Parentheses
    if (char === '(' || char === ')') {
      tokens.push({ type: 'parenthesis', value: char, color: '#ffd700' }); // Gold for parentheses
      i++;
      continue;
    }

    // Brackets
    if (char === '[' || char === ']') {
      tokens.push({ type: 'bracket', value: char, color: '#ffd700' }); // Gold for brackets
      i++;
      continue;
    }

    // Comma
    if (char === ',') {
      tokens.push({ type: 'comma', value: char, color: '#d4d4d4' });
      i++;
      continue;
    }

    // Identifiers (field names, functions, keywords)
    if (/[a-zA-Z_]/.test(char)) {
      let ident = '';
      while (i < expression.length && /[a-zA-Z0-9_]/.test(expression[i])) {
        ident += expression[i];
        i++;
      }

      // Check if it's followed by '(' - then it's a function
      const nextNonSpace = expression.slice(i).match(/^\s*\(/);
      if (nextNonSpace || HELPER_FUNCTIONS.has(ident)) {
        tokens.push({ type: 'function', value: ident, color: '#dcdcaa' }); // Function color (yellow)
      } else if (BOOLEAN_LITERALS.has(ident.toLowerCase())) {
        tokens.push({ type: 'boolean', value: ident, color: '#569cd6' }); // Boolean color (blue)
      } else if (COMMON_FIELDS.has(ident)) {
        tokens.push({ type: 'field', value: ident, color: '#9cdcfe' }); // Field color (light blue)
      } else {
        // Unknown identifier - likely a custom field
        tokens.push({ type: 'field', value: ident, color: '#9cdcfe' }); // Treat as field
      }
      continue;
    }

    // Unknown character - just add as text
    tokens.push({ type: 'text', value: char, color: 'inherit' });
    i++;
  }

  return tokens;
}

/**
 * Convert tokens to HTML string with inline styles
 */
export function tokensToHTML(tokens: HighlightedToken[]): string {
  return tokens
    .map(token => {
      if (token.type === 'text' && token.color === 'inherit') {
        return token.value;
      }
      return `<span style="color: ${token.color}">${escapeHTML(token.value)}</span>`;
    })
    .join('');
}

/**
 * Convert tokens to React elements (for use in React components)
 */
export function tokensToReactElements(tokens: HighlightedToken[]): React.ReactElement[] {
  return tokens.map((token, i) => {
    if (token.type === 'text' && token.color === 'inherit') {
      return <span key={i}>{token.value}</span>;
    }
    return (
      <span key={i} style={{ color: token.color }}>
        {token.value}
      </span>
    );
  });
}

/**
 * Get theme colors for syntax highlighting
 * Returns colors based on MUI theme mode
 */
export function getSyntaxColors(isDarkMode: boolean = true) {
  if (isDarkMode) {
    return {
      field: '#9cdcfe',      // Light blue for field names
      operator: '#d4d4d4',   // Light gray for operators
      function: '#dcdcaa',   // Yellow for functions
      string: '#ce9178',     // Orange for strings
      number: '#b5cea8',     // Light green for numbers
      boolean: '#569cd6',    // Blue for booleans
      parenthesis: '#ffd700',// Gold for parentheses
      bracket: '#ffd700',    // Gold for brackets
      comma: '#d4d4d4',      // Light gray for commas
    };
  } else {
    return {
      field: '#001080',      // Dark blue for field names
      operator: '#000000',   // Black for operators
      function: '#795e26',   // Brown for functions
      string: '#a31515',     // Dark red for strings
      number: '#098658',     // Dark green for numbers
      boolean: '#0000ff',    // Blue for booleans
      parenthesis: '#af00db',// Purple for parentheses
      bracket: '#af00db',    // Purple for brackets
      comma: '#000000',      // Black for commas
    };
  }
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

