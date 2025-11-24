import React, { useRef, useEffect, useState, useCallback, useMemo } from 'react';
import { Box, InputLabel, FormHelperText, useTheme, OutlinedInput } from '@mui/material';
import { highlightFilterExpression } from '@/lib/filterSyntaxHighlight';
import { highlightBPFExpression } from '@/lib/bpfSyntaxHighlight';
import { highlightRegexPattern } from '@/lib/regexSyntaxHighlight';
import type { RegexToken } from '@/lib/regexSyntaxHighlight';
import type { BPFToken } from '@/lib/bpfSyntaxHighlight';
import type { FilterToken } from '@/lib/filterSyntaxHighlight';

type SyntaxType = 'filter' | 'bpf' | 'regex';
type Token = RegexToken | BPFToken | FilterToken;

interface SyntaxHighlightedInputProps {
  /** The syntax type to highlight */
  syntaxType: SyntaxType;
  /** The input value */
  value: string;
  /** Change handler */
  onChange: (value: string) => void;
  /** Whether to show syntax highlighting (default: true) */
  enableHighlighting?: boolean;
  /** Label for the input */
  label?: string;
  /** Helper text */
  helperText?: string;
  /** Placeholder */
  placeholder?: string;
  /** Whether multiline */
  multiline?: boolean;
  /** Number of rows (for multiline) */
  rows?: number;
  /** Full width */
  fullWidth?: boolean;
  /** Size */
  size?: 'small' | 'medium';
  /** Additional props */
  [key: string]: any;
}

/**
 * A text input field with inline syntax highlighting
 * Uses an overlay approach with transparent text to show highlighting
 * Optimized with memoization to prevent lag
 */
export default function SyntaxHighlightedInput({
  syntaxType,
  value,
  onChange,
  enableHighlighting = true,
  label,
  helperText,
  placeholder,
  multiline = false,
  rows = 4,
  fullWidth = true,
  size = 'medium',
  ...otherProps
}: SyntaxHighlightedInputProps) {
  const theme = useTheme();
  const textareaRef = useRef<HTMLTextAreaElement | HTMLInputElement>(null);
  const [isFocused, setIsFocused] = useState(false);

  // Memoize tokens to prevent re-computation on every render
  const tokens = useMemo(() => {
    if (!enableHighlighting || !value) {
      return [];
    }

    let newTokens: Token[] = [];
    try {
      switch (syntaxType) {
        case 'filter':
          newTokens = highlightFilterExpression(value);
          break;
        case 'bpf':
          newTokens = highlightBPFExpression(value);
          break;
        case 'regex':
          newTokens = highlightRegexPattern(value);
          break;
      }
    } catch (error) {
      // If highlighting fails, return empty tokens
      console.warn('Syntax highlighting error:', error);
      return [];
    }
    return newTokens;
  }, [value, syntaxType, enableHighlighting]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
    onChange(e.target.value);
  };

  const handleFocus = () => setIsFocused(true);
  const handleBlur = () => setIsFocused(false);

  const inputPadding = size === 'small' ? '8.5px 14px' : '16.5px 14px';
  const lineHeight = '1.4375em';
  const fontSize = size === 'small' ? '0.875rem' : '0.95rem';

  // Only show highlighting when not focused to improve performance
  const showHighlighting = enableHighlighting && tokens.length > 0 && !isFocused;

  // Get text color from theme (for both light and dark modes)
  const textColor = theme.palette.text.primary;
  const bgColor = theme.palette.background.default;

  return (
    <Box sx={{ width: fullWidth ? '100%' : 'auto' }}>
      {label && (
        <InputLabel 
          shrink 
          sx={{ 
            mb: 0.5, 
            fontSize: '0.875rem',
            color: isFocused ? 'primary.main' : 'text.secondary',
            fontWeight: 500,
          }}
        >
          {label}
        </InputLabel>
      )}
      
      <Box sx={{ position: 'relative', width: '100%' }}>
        {/* Syntax-highlighted overlay - only when not focused */}
        {showHighlighting && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              pointerEvents: 'none',
              overflow: 'hidden',
              padding: inputPadding,
              fontFamily: 'monospace',
              fontSize: fontSize,
              lineHeight: lineHeight,
              whiteSpace: multiline ? 'pre-wrap' : 'pre',
              wordBreak: multiline ? 'break-word' : 'normal',
              color: 'transparent',
              userSelect: 'none',
              border: '1px solid transparent',
              borderRadius: '4px',
              zIndex: 0,
              backgroundColor: 'transparent', // Ensure overlay is transparent
            }}
          >
            {tokens.map((token, i) => {
              if (token.type === 'text' && token.color === 'inherit') {
                return <span key={i} style={{ color: textColor }}>{token.value}</span>;
              }
              return (
                <span key={i} style={{ color: token.color }}>
                  {token.value}
                </span>
              );
            })}
          </Box>
        )}

        {/* Actual input */}
        <OutlinedInput
          {...otherProps}
          inputRef={textareaRef}
          value={value}
          onChange={handleChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          placeholder={placeholder}
          multiline={multiline}
          rows={multiline ? rows : undefined}
          fullWidth={fullWidth}
          size={size}
          sx={{
            fontFamily: 'monospace',
            fontSize: fontSize,
            position: 'relative',
            zIndex: 1,
            backgroundColor: bgColor, // Use theme background color
            '& .MuiOutlinedInput-notchedOutline': {
              borderColor: theme.palette.divider,
            },
            '& textarea, & input': {
              fontFamily: 'monospace',
              fontSize: fontSize,
              lineHeight: lineHeight,
              // Only make text transparent when showing highlighting and not focused
              color: showHighlighting ? 'transparent' : textColor,
              // Always show caret
              caretColor: `${textColor} !important`,
              backgroundColor: 'transparent',
              '&::selection': {
                backgroundColor: showHighlighting ? 'rgba(100, 150, 255, 0.3)' : undefined,
              },
            },
          }}
        />
      </Box>

      {helperText && (
        <FormHelperText sx={{ mx: 1.75, mt: 0.5 }}>
          {helperText}
        </FormHelperText>
      )}
    </Box>
  );
}

/**
 * Multiline variant with syntax highlighting
 */
export function SyntaxHighlightedTextArea({
  syntaxType,
  value,
  onChange,
  enableHighlighting = true,
  rows = 4,
  ...otherProps
}: SyntaxHighlightedInputProps) {
  return (
    <SyntaxHighlightedInput
      syntaxType={syntaxType}
      value={value}
      onChange={onChange}
      enableHighlighting={enableHighlighting}
      multiline={true}
      rows={rows}
      {...otherProps}
    />
  );
}

