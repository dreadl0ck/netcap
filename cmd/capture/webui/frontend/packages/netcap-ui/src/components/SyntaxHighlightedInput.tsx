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

import React, { useRef, useEffect, useState, useMemo } from 'react';
import { Box, InputLabel, FormHelperText, useTheme } from '@mui/material';
import { highlightFilterExpression } from '../lib/filterSyntaxHighlight';
import { highlightBPFExpression } from '../lib/bpfSyntaxHighlight';
import { highlightRegexPattern } from '../lib/regexSyntaxHighlight';
import type { RegexToken } from '../lib/regexSyntaxHighlight';
import type { BPFToken } from '../lib/bpfSyntaxHighlight';
import type { FilterToken } from '../lib/filterSyntaxHighlight';
import { escapeHTMLPreservingLineBreaks, safeCSSColor } from '../lib/html';

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
 * Uses contentEditable div for native colored text rendering and scrolling
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
  const editableRef = useRef<HTMLDivElement>(null);
  const [isFocused, setIsFocused] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const isUpdatingRef = useRef(false);
  const isTypingRef = useRef(false);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);

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

  const inputPadding = size === 'small' ? '8.5px 14px' : '16.5px 14px';
  const lineHeight = '1.4375em';
  const fontSize = size === 'small' ? '0.875rem' : '0.95rem';

  // Get text color from theme (for both light and dark modes)
  const textColor = theme.palette.text.primary;
  const bgColor = theme.palette.background.paper;

  // Show highlighting only when not typing and highlighting is enabled
  const showHighlighting = enableHighlighting && tokens.length > 0 && !isTyping;

  // Calculate height based on rows
  const minHeight = multiline ? `calc(${rows} * ${lineHeight} + 17px)` : undefined;

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, []);

  // Update contentEditable div when highlighting state changes (but not while typing)
  useEffect(() => {
    if (!editableRef.current || isUpdatingRef.current || isTyping) {
      return;
    }

    // Only update if content has changed or we need to apply syntax highlighting
    const currentText = editableRef.current.innerText || '';
    if (currentText === value) {
      // Value is same, just need to update highlighting
      const selection = window.getSelection();
      const range = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
      const cursorOffset = range ? getCursorOffset(editableRef.current, range) : 0;

      updateContent();

      if (cursorOffset !== null && isFocused) {
        requestAnimationFrame(() => {
          setCursorOffset(editableRef.current!, cursorOffset);
        });
      }
    }
  }, [showHighlighting, isTyping]);

  // Update when value changes externally (from prop)
  useEffect(() => {
    if (!editableRef.current || isUpdatingRef.current) {
      return;
    }

    const currentText = editableRef.current.innerText || '';
    if (currentText !== value) {
      // Value changed externally
      const selection = window.getSelection();
      const range = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
      const cursorOffset = range ? getCursorOffset(editableRef.current, range) : 0;

      updateContent();

      if (cursorOffset !== null && isFocused) {
        requestAnimationFrame(() => {
          setCursorOffset(editableRef.current!, cursorOffset);
        });
      }
    }
  }, [value]);

  // Get cursor offset from start of contentEditable
  function getCursorOffset(element: HTMLElement, range: Range): number {
    const preRange = range.cloneRange();
    preRange.selectNodeContents(element);
    preRange.setEnd(range.endContainer, range.endOffset);
    return preRange.toString().length;
  }

  // Set cursor offset from start of contentEditable
  function setCursorOffset(element: HTMLElement, offset: number) {
    const selection = window.getSelection();
    if (!selection) return;

    let currentOffset = 0;
    let found = false;

    function traverse(node: Node): boolean {
      if (node.nodeType === Node.TEXT_NODE) {
        const textLength = node.textContent?.length || 0;
        if (currentOffset + textLength >= offset) {
          const range = document.createRange();
          range.setStart(node, Math.min(offset - currentOffset, textLength));
          range.collapse(true);
          if (selection) {
            selection.removeAllRanges();
            selection.addRange(range);
          }
          return true;
        }
        currentOffset += textLength;
      } else {
        for (let i = 0; i < node.childNodes.length; i++) {
          if (traverse(node.childNodes[i])) {
            return true;
          }
        }
      }
      return false;
    }

    traverse(element);
  }

  // Update the contentEditable div with highlighted content
  function updateContent() {
    if (!editableRef.current) return;

    if (showHighlighting) {
      // Render with syntax highlighting
      editableRef.current.innerHTML = tokens
        .map((token) => {
          const color = token.type === 'text' && token.color === 'inherit' ? textColor : token.color;
          // safeCSSColor because this is interpolated into a style attribute,
          // not a text node: escaping the value alone would not stop a colour
          // from closing the attribute and adding an event handler.
          const escapedValue = escapeHTMLPreservingLineBreaks(token.value);
          return `<span style="color: ${safeCSSColor(color)}">${escapedValue}</span>`;
        })
        .join('');
    } else {
      // Render as plain text but preserve line breaks
      editableRef.current.innerHTML = escapeHTMLPreservingLineBreaks(value);
    }

    // Show placeholder if empty
    if (!value && placeholder) {
      editableRef.current.setAttribute('data-placeholder', placeholder);
    } else {
      editableRef.current.removeAttribute('data-placeholder');
    }
  }

  // Handle input changes
  const handleInput = () => {
    if (!editableRef.current) return;

    // Mark as typing using ref to avoid re-renders on every keystroke
    if (!isTypingRef.current) {
      isTypingRef.current = true;
      setIsTyping(true);
    }

    // Clear existing timeout
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }

    // Get value - use innerText to preserve line breaks from <br> tags
    isUpdatingRef.current = true;
    const newValue = editableRef.current.innerText || '';
    
    // Use queueMicrotask to defer onChange slightly without blocking input
    queueMicrotask(() => {
      onChange(newValue);
      isUpdatingRef.current = false;
    });

    // Re-enable syntax highlighting after user stops typing
    typingTimeoutRef.current = setTimeout(() => {
      isTypingRef.current = false;
      setIsTyping(false);
      typingTimeoutRef.current = null;
    }, 150);
  };

  const handleFocus = () => setIsFocused(true);
  
  const handleBlur = () => {
    setIsFocused(false);
    // Apply syntax highlighting immediately when losing focus
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = null;
    }
    isTypingRef.current = false;
    setIsTyping(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Allow tab key to insert tab character
    if (e.key === 'Tab') {
      e.preventDefault();
      document.execCommand('insertText', false, '  ');
    }
    // Handle Enter key to insert line break consistently
    if (e.key === 'Enter') {
      e.preventDefault();
      document.execCommand('insertLineBreak');
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    // Prevent default paste behavior and insert plain text only
    e.preventDefault();
    const text = e.clipboardData.getData('text/plain');
    document.execCommand('insertText', false, text);
  };

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
      
      <Box
        ref={editableRef}
        contentEditable
        onInput={handleInput}
        onFocus={handleFocus}
        onBlur={handleBlur}
        onKeyDown={handleKeyDown}
        onPaste={handlePaste}
        spellCheck={false}
            sx={{
              fontFamily: 'monospace',
              fontSize: fontSize,
              lineHeight: lineHeight,
          padding: inputPadding,
          border: `1px solid ${isFocused ? theme.palette.primary.main : theme.palette.divider}`,
          borderRadius: '4px',
          backgroundColor: bgColor,
          color: textColor,
          minHeight: minHeight,
          maxHeight: multiline ? '400px' : undefined,
          overflowY: multiline ? 'auto' : 'hidden',
          overflowX: 'auto',
              whiteSpace: multiline ? 'pre-wrap' : 'pre',
              wordBreak: multiline ? 'break-word' : 'normal',
          outline: 'none',
          cursor: 'text',
          transition: 'border-color 0.2s',
          '&:hover': {
            borderColor: isFocused ? theme.palette.primary.main : theme.palette.text.primary,
          },
          '&:focus': {
            borderColor: theme.palette.primary.main,
            borderWidth: '2px',
            padding: size === 'small' ? '7.5px 13px' : '15.5px 13px',
          },
          '&[data-placeholder]:empty::before': {
            content: 'attr(data-placeholder)',
            color: theme.palette.text.disabled,
            fontStyle: 'italic',
            },
          }}
        />

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
