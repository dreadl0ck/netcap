import React, { useRef, useEffect, useState } from 'react';
import { Box, Autocomplete, TextField, AutocompleteRenderInputParams } from '@mui/material';
import { highlightFilterExpression } from '@/lib/filterSyntaxHighlight';
import type { FilterToken } from '@/lib/filterSyntaxHighlight';

interface SyntaxHighlightedAutocompleteProps {
  /** The input value */
  value: string;
  /** Change handler */
  onChange: (value: string) => void;
  /** Input reference */
  inputRef?: React.Ref<HTMLInputElement>;
  /** Autocomplete options */
  options: string[];
  /** Whether dropdown is open */
  open?: boolean;
  /** Open state change handler */
  onOpen?: () => void;
  /** Close state change handler */
  onClose?: (event: React.SyntheticEvent, reason: string) => void;
  /** Highlight change handler */
  onHighlightChange?: (event: React.SyntheticEvent, option: string | null, reason: string) => void;
  /** Input change handler */
  onInputChange?: (event: React.SyntheticEvent, value: string, reason: string) => void;
  /** Option select handler */
  onOptionSelect?: (event: React.SyntheticEvent, value: string | null, reason: string) => void;
  /** Filter options function */
  filterOptions?: (options: string[]) => string[];
  /** Render input props */
  renderInputProps?: Partial<AutocompleteRenderInputParams>;
  /** Label */
  label?: string;
  /** Placeholder */
  placeholder?: string;
  /** Size */
  size?: 'small' | 'medium';
  /** Loading state */
  loading?: boolean;
  /** Disabled state */
  disabled?: boolean;
  /** Other TextField props for renderInput */
  [key: string]: any;
}

/**
 * An Autocomplete component with inline syntax highlighting for filter expressions
 */
export default function SyntaxHighlightedAutocomplete({
  value,
  onChange,
  inputRef,
  options,
  open,
  onOpen,
  onClose,
  onHighlightChange,
  onInputChange,
  onOptionSelect,
  filterOptions,
  renderInputProps,
  label,
  placeholder,
  size = 'small',
  loading,
  disabled,
  ...otherProps
}: SyntaxHighlightedAutocompleteProps) {
  const [tokens, setTokens] = useState<FilterToken[]>([]);

  // Update highlighting when value changes
  useEffect(() => {
    if (!value) {
      setTokens([]);
      return;
    }
    const newTokens = highlightFilterExpression(value);
    setTokens(newTokens);
  }, [value]);

  return (
    <Box sx={{ position: 'relative', width: '100%' }}>
      {/* Syntax-highlighted overlay */}
      {tokens.length > 0 && (
        <Box
          sx={{
            position: 'absolute',
            top: '8px',
            left: '14px',
            right: '14px',
            pointerEvents: 'none',
            overflow: 'hidden',
            zIndex: 1,
            fontFamily: 'monospace',
            fontSize: '0.95rem',
            lineHeight: '1.4375em',
            whiteSpace: 'nowrap',
            color: 'transparent',
            userSelect: 'none',
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
      )}

      {/* Autocomplete with transparent text */}
      <Autocomplete
        freeSolo
        fullWidth
        value={value}
        inputValue={value}
        onChange={(event, newValue, reason) => {
          if (onOptionSelect) {
            onOptionSelect(event, newValue, reason);
          }
        }}
        onInputChange={(event, newValue, reason) => {
          onChange(newValue);
          if (onInputChange) {
            onInputChange(event, newValue, reason);
          }
        }}
        options={options}
        open={open}
        onOpen={onOpen}
        onClose={onClose}
        onHighlightChange={onHighlightChange}
        filterOptions={filterOptions || ((options) => options)}
        loading={loading}
        disabled={disabled}
        autoHighlight
        selectOnFocus={false}
        clearOnBlur={false}
        handleHomeEndKeys
        disableClearable={true}
        renderInput={(params) => (
          <TextField
            {...params}
            {...renderInputProps}
            inputRef={inputRef}
            size={size}
            label={label}
            placeholder={placeholder}
            sx={{
              '& .MuiInputBase-input': {
                fontFamily: 'monospace',
                fontSize: '0.95rem',
                color: tokens.length > 0 ? 'transparent' : 'text.primary',
                caretColor: 'text.primary',
                '&::selection': {
                  backgroundColor: tokens.length > 0 ? 'rgba(100, 150, 255, 0.3)' : undefined,
                },
              },
            }}
            {...otherProps}
          />
        )}
      />
    </Box>
  );
}

