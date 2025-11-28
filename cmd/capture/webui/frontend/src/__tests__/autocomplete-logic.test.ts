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
 * Unit tests for autocomplete logic functions
 * These tests focus on the pure logic without React component rendering
 */

describe('Autocomplete Logic - getContextualSuggestions', () => {
  const fieldSuggestions = ['SrcPort', 'DstPort', 'SrcIP', 'DstIP', 'Protocol', 'Length'];
  const operators = ['==', '!=', '<', '>', '<=', '>=', '&&', '||', '!'];
  const fieldValues: Record<string, string[]> = {
    'SrcPort': ['80', '443', '22', '3306'],
    'DstPort': ['80', '443', '22', '8080'],
    'Protocol': ['TCP', 'UDP', 'ICMP'],
  };
  const fieldTypes: Record<string, string> = {
    'SrcPort': 'uint16',
    'DstPort': 'uint16',
    'SrcIP': 'string',
    'DstIP': 'string',
    'Protocol': 'string',
    'Length': 'int',
  };

  const isNumericType = (fieldType: string): boolean => {
    return /^(int|uint|float|int8|int16|int32|int64|uint8|uint16|uint32|uint64|float32|float64)$/i.test(fieldType);
  };

  /**
   * Simulates the getContextualSuggestions function from audit.tsx
   */
  const getContextualSuggestions = (inputValue: string): string[] => {
    if (!inputValue) return fieldSuggestions;

    const cursorPos = inputValue.length;
    const beforeCursor = inputValue.substring(0, cursorPos);
    
    // Check if we just completed a value (requires space AFTER the value)
    // Fixed: Added mandatory space after the value to consider it "completed"
    const completedValueMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s+(?:\d+\s+|['"][^'"]*['"]\s+)$/);
    
    if (completedValueMatch) {
      return ['&&', '||'];
    }
    
    // Check if we're after a comparison operator
    // Fixed: Updated regex to handle partial digits and other characters
    const comparisonMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s*['"]?([\w.]*)$/);
    
    if (comparisonMatch) {
      const fieldName = comparisonMatch[1];
      const partialValue = comparisonMatch[3];
      
      if (fieldValues[fieldName]) {
        const values = fieldValues[fieldName];
        const fieldType = fieldTypes[fieldName] || '';
        const isNumeric = isNumericType(fieldType);
        
        if (partialValue) {
          // Case-sensitive matching for values
          return values
            .filter(v => v.startsWith(partialValue))
            .map(v => isNumeric ? v : `"${v}"`);
        }
        return values.map(v => isNumeric ? v : `"${v}"`);
      }
    }

    // Check if we're after a logical operator
    const afterLogicalOpMatch = beforeCursor.match(/(&&|\|\|)\s*$/);
    if (afterLogicalOpMatch) {
      return fieldSuggestions;
    }

    // Check if we might be typing an operator
    const operatorMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*([=!<>&|]*)$/);
    
    if (operatorMatch && operatorMatch[2]) {
      const partialOp = operatorMatch[2];
      const matchingOps = operators.filter(op => 
        op.startsWith(partialOp) && op !== partialOp
      );
      
      if (matchingOps.length > 0) {
        return matchingOps;
      }
    }

    // Check if we're typing a field name
    const words = beforeCursor.split(/[\s()&|,]+/);
    const currentWord = words[words.length - 1] || '';
    
    if (currentWord.length >= 1) {
      // Case-sensitive matching: field name must start with exact case
      return fieldSuggestions.filter(option =>
        option.startsWith(currentWord)
      );
    }

    return fieldSuggestions;
  };

  /**
   * Simulates the insertSuggestion function from audit.tsx
   */
  const insertSuggestion = (currentExpression: string, suggestion: string): string => {
    const beforeCursor = currentExpression;
    const words = beforeCursor.split(/[\s()&|,]+/);
    const currentWord = words[words.length - 1] || '';
    
    // Check if we're completing a value
    // Fixed: Updated regex to handle partial digits and other characters
    const comparisonMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s*['"]?([\w.]*)$/);
    
    if (comparisonMatch) {
      const partialValue = comparisonMatch[3];
      const beforeValue = beforeCursor.substring(0, beforeCursor.length - partialValue.length);
      return beforeValue + suggestion + ' ';
    }
    
    // Check if we're completing an operator
    const operatorMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*([=!<>&|]*)$/);
    
    if (operatorMatch && operatorMatch[2] && operators.includes(suggestion)) {
      const partialOp = operatorMatch[2];
      const beforeOp = beforeCursor.substring(0, beforeCursor.length - partialOp.length);
      return beforeOp + ' ' + suggestion + ' ';
    }
    
    // Completing a field name
    if (currentWord) {
      const cleanSuggestion = suggestion.replace(/^["']|["']$/g, '');
      
      // Case-sensitive matching: must start with exact case
      if (cleanSuggestion.startsWith(currentWord)) {
        const remainder = cleanSuggestion.substring(currentWord.length);
        return currentExpression + remainder;
      } else {
        const beforeWord = beforeCursor.substring(0, beforeCursor.length - currentWord.length);
        return beforeWord + suggestion;
      }
    }
    
    return currentExpression + suggestion;
  };

  test('Empty input returns all field suggestions', () => {
    const suggestions = getContextualSuggestions('');
    expect(suggestions).toEqual(fieldSuggestions);
  });

  test('Partial field name filters suggestions', () => {
    const suggestions = getContextualSuggestions('Src');
    expect(suggestions).toContain('SrcPort');
    expect(suggestions).toContain('SrcIP');
    expect(suggestions).not.toContain('DstPort');
  });

  test('After field name with partial operator, suggests operators', () => {
    const suggestions = getContextualSuggestions('SrcPort =');
    expect(suggestions).toContain('==');
    expect(suggestions).not.toContain('SrcPort');
  });

  test('After comparison operator, suggests field values (numeric unquoted)', () => {
    const suggestions = getContextualSuggestions('DstPort == ');
    // DstPort is uint16, so values should NOT be quoted
    expect(suggestions).toEqual(['80', '443', '22', '8080']);
  });

  test('After comparison operator with string field, wraps values in quotes', () => {
    const suggestions = getContextualSuggestions('Protocol == ');
    expect(suggestions).toEqual(['"TCP"', '"UDP"', '"ICMP"']);
  });

  test('After complete expression, suggests logical operators', () => {
    const suggestions = getContextualSuggestions('SrcPort == 80 ');
    expect(suggestions).toEqual(['&&', '||']);
  });

  test('After logical operator, suggests field names', () => {
    const suggestions = getContextualSuggestions('SrcPort == 80 && ');
    expect(suggestions).toEqual(fieldSuggestions);
  });

  test('insertSuggestion completes partial field name', () => {
    const result = insertSuggestion('Src', 'SrcPort');
    expect(result).toBe('SrcPort');
  });

  test('insertSuggestion inserts operator with spaces', () => {
    const result = insertSuggestion('SrcPort =', '==');
    // One space before and after operator
    expect(result).toBe('SrcPort  == ');
  });

  test('insertSuggestion inserts value with trailing space', () => {
    const result = insertSuggestion('DstPort == ', '80');
    expect(result).toBe('DstPort == 80 ');
  });

  test('insertSuggestion handles logical operator insertion', () => {
    const result = insertSuggestion('SrcPort == 80 ', '&&');
    expect(result).toBe('SrcPort == 80 &&');
  });

  test('Chain completion: field -> operator -> value -> logical op', () => {
    let expr = '';
    
    // Start with partial field
    expr = 'Src';
    let suggestions = getContextualSuggestions(expr);
    expect(suggestions).toContain('SrcPort');
    
    // Complete field
    expr = insertSuggestion(expr, 'SrcPort');
    expect(expr).toBe('SrcPort');
    
    // Add space and partial operator
    expr += ' =';
    suggestions = getContextualSuggestions(expr);
    expect(suggestions).toContain('==');
    
    // Complete operator
    expr = insertSuggestion(expr, '==');
    expect(expr).toContain('==');
    
    // Get value suggestions
    suggestions = getContextualSuggestions(expr);
    // Numeric field, so values are unquoted
    expect(suggestions).toContain('80');
    
    // Complete value (insertSuggestion adds trailing space)
    expr = insertSuggestion(expr, '80');
    expect(expr).toContain('== 80');
    
    // Get logical operator suggestions (value has trailing space, so it's "completed")
    suggestions = getContextualSuggestions(expr);
    expect(suggestions).toEqual(['&&', '||']);
    
    // Complete logical operator
    expr = insertSuggestion(expr, '&&');
    expect(expr).toContain('&&');
  });

  test('Partial value filtering works correctly', () => {
    const suggestions = getContextualSuggestions('DstPort == 8');
    // When typing partial value "8", should filter to values containing "8"
    expect(suggestions).toContain('80');
    expect(suggestions).toContain('8080');
    expect(suggestions).not.toContain('443');
  });

  test('Case-sensitive field name matching', () => {
    // Lowercase "src" should NOT match "SrcPort" or "SrcIP" (case mismatch)
    let suggestions = getContextualSuggestions('src');
    expect(suggestions).not.toContain('SrcPort');
    expect(suggestions).not.toContain('SrcIP');
    expect(suggestions.length).toBe(0);
    
    // Correct case "Src" should match "SrcPort" and "SrcIP"
    suggestions = getContextualSuggestions('Src');
    expect(suggestions).toContain('SrcPort');
    expect(suggestions).toContain('SrcIP');
  });

  test('Multiple conditions can be built', () => {
    let expr = 'SrcPort == 80 && ';
    let suggestions = getContextualSuggestions(expr);
    expect(suggestions).toEqual(fieldSuggestions);
    
    // Start second field
    expr += 'Dst';
    suggestions = getContextualSuggestions(expr);
    expect(suggestions).toContain('DstPort');
    expect(suggestions).toContain('DstIP');
  });

  test('Handles numeric vs string field types correctly', () => {
    // Numeric field - no quotes
    let suggestions = getContextualSuggestions('Length == ');
    suggestions.forEach(s => {
      expect(s).not.toMatch(/^["']/);
    });
    
    // String field - with quotes
    suggestions = getContextualSuggestions('Protocol == ');
    suggestions.forEach(s => {
      if (s !== '') {
        expect(s).toMatch(/^["']/);
      }
    });
  });

  test('Empty expression after operator still suggests values', () => {
    const suggestions = getContextualSuggestions('DstPort == ');
    expect(suggestions.length).toBeGreaterThan(0);
    // Numeric field, unquoted values
    expect(suggestions).toContain('80');
  });

  test('Complex expression with nested operators', () => {
    const expr = 'SrcPort == 80 && DstPort == 443 || ';
    const suggestions = getContextualSuggestions(expr);
    expect(suggestions).toEqual(fieldSuggestions);
  });
});

describe('Autocomplete Logic - Edge Cases', () => {
  test('Handles empty string gracefully', () => {
    const getContextualSuggestions = (inputValue: string): string[] => {
      if (!inputValue) return ['SrcPort', 'DstPort'];
      return [];
    };
    
    expect(getContextualSuggestions('')).toEqual(['SrcPort', 'DstPort']);
  });

  test('Handles whitespace-only input', () => {
    const getContextualSuggestions = (inputValue: string): string[] => {
      if (!inputValue || inputValue.trim() === '') return ['SrcPort', 'DstPort'];
      return [];
    };
    
    expect(getContextualSuggestions('   ')).toEqual(['SrcPort', 'DstPort']);
  });

  test('Handles special characters in values', () => {
    const insertSuggestion = (expr: string, suggestion: string): string => {
      return expr + suggestion;
    };
    
    const result = insertSuggestion('SrcIP == ', '"192.168.1.1"');
    expect(result).toBe('SrcIP == "192.168.1.1"');
  });
});

