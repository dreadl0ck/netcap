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
import { Box, useTheme } from '@mui/material';
import { highlightBPFExpression } from '../lib/bpfSyntaxHighlight';

interface BPFExpressionHighlightProps {
  expression: string;
  /** Additional styles to apply to the container */
  sx?: any;
  /** Whether to use monospace font (default: true) */
  monospace?: boolean;
  /** Font size (default: '0.95rem') */
  fontSize?: string;
  /** Whether to wrap text (default: false) */
  wrap?: boolean;
}

/**
 * Component that displays a syntax-highlighted BPF filter expression
 * Supports tcpdump-style BPF syntax
 */
export default function BPFExpressionHighlight({
  expression,
  sx,
  monospace = true,
  fontSize = '0.95rem',
  wrap = false,
}: BPFExpressionHighlightProps) {
  const theme = useTheme();

  // Tokenize and highlight the expression
  const tokens = highlightBPFExpression(expression);

  // If empty expression, show nothing
  if (!expression || tokens.length === 0) {
    return null;
  }

  return (
    <Box
      component="span"
      sx={{
        fontFamily: monospace ? 'monospace' : 'inherit',
        fontSize: fontSize,
        whiteSpace: wrap ? 'pre-wrap' : 'nowrap',
        wordBreak: wrap ? 'break-word' : 'normal',
        display: 'inline-block',
        ...sx,
      }}
    >
      {tokens.map((token, i) => {
        if (token.type === 'text' && token.color === 'inherit') {
          return <span key={i}>{token.value}</span>;
        }
        return (
          <span key={i} style={{ color: token.color }}>
            {token.value}
          </span>
        );
      })}
    </Box>
  );
}

/**
 * Block variant for displaying BPF expressions
 * Typically used in code blocks or detailed views
 */
export function BPFExpressionBlock({
  expression,
  sx,
}: {
  expression: string;
  sx?: any;
}) {
  return (
    <Box
      sx={{
        p: 2,
        bgcolor: 'action.hover',
        borderRadius: 1,
        overflow: 'auto',
        ...sx,
      }}
    >
      <BPFExpressionHighlight
        expression={expression}
        wrap={true}
        monospace={true}
        fontSize="0.95rem"
      />
    </Box>
  );
}

