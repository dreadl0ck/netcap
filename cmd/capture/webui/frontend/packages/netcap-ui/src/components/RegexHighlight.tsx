import React from 'react';
import { Box, useTheme } from '@mui/material';
import { highlightRegexPattern } from '../lib/regexSyntaxHighlight';

interface RegexHighlightProps {
  pattern: string;
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
 * Component that displays a syntax-highlighted regex pattern
 * Supports standard regex syntax including flags, groups, character classes, etc.
 */
export default function RegexHighlight({
  pattern,
  sx,
  monospace = true,
  fontSize = '0.95rem',
  wrap = false,
}: RegexHighlightProps) {
  const theme = useTheme();

  // Tokenize and highlight the pattern
  const tokens = highlightRegexPattern(pattern);

  // If empty pattern, show nothing
  if (!pattern || tokens.length === 0) {
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
 * Block variant for displaying regex patterns
 * Typically used in code blocks or detailed views
 */
export function RegexBlock({
  pattern,
  sx,
}: {
  pattern: string;
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
      <RegexHighlight
        pattern={pattern}
        wrap={true}
        monospace={true}
        fontSize="0.95rem"
      />
    </Box>
  );
}

