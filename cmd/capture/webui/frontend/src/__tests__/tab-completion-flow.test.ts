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
 * Unit test for TAB/ENTER completion flow
 * Tests the exact sequence: field name → operator → value
 * Each completion should insert the item + single space, then show next suggestions
 */

describe('TAB/ENTER Completion Flow', () => {
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
    return /^(int|uint|float|int8|int16|int32|int64|uint8|uint16|uint32|uint64|float32|float64|byte)$/i.test(fieldType);
  };

  /**
   * Simulates the getContextualSuggestions function from audit.tsx
   */
  const getContextualSuggestions = (inputValue: string): string[] => {
    if (!inputValue) return fieldSuggestions;

    const cursorPos = inputValue.length;
    const beforeCursor = inputValue.substring(0, cursorPos);
    
    // Check if we just completed a value (requires space AFTER the value)
    const completedValueMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s+(?:\d+\s+|['"][^'"]*['"]\s+)$/);
    
    if (completedValueMatch) {
      return ['&&', '||'];
    }
    
    // Check if we're after a comparison operator
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

    // If we have a complete field name followed by whitespace (no operator yet),
    // don't show suggestions - wait for user to start typing an operator
    // This matches: "SrcPort " or "SrcPort && DstPort "
    const fieldNameWithSpaceMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s+$/);
    if (fieldNameWithSpaceMatch && !beforeCursor.match(/(==|!=|<|>|<=|>=)\s*$/)) {
      // We have a field name followed by space, but no operator
      // Don't show field suggestions - wait for operator input
      return [];
    }

    return fieldSuggestions;
  };

  /**
   * Simulates the insertSuggestion function from audit.tsx (FIXED VERSION)
   */
  const insertSuggestion = (currentExpression: string, suggestion: string): string => {
    const beforeCursor = currentExpression;
    const words = beforeCursor.split(/[\s()&|,]+/);
    const currentWord = words[words.length - 1] || '';
    
    // Check if we're completing a value
    const comparisonMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*(==|!=|<|>|<=|>=)\s*['"]?([\w.]*)$/);
    
    if (comparisonMatch) {
      const partialValue = comparisonMatch[3];
      const beforeValue = beforeCursor.substring(0, beforeCursor.length - partialValue.length);
      // Add trailing space after value for flow into next operator
      return beforeValue + suggestion + ' ';
    }
    
    // Check if we're completing an operator
    const operatorMatch = beforeCursor.match(/(\w+(?:\[\d+\])?(?:\.\w+)*)\s*([=!<>&|]*)$/);
    
    if (operatorMatch && operatorMatch[2] && operators.includes(suggestion)) {
      const partialOp = operatorMatch[2];
      const beforeOp = beforeCursor.substring(0, beforeCursor.length - partialOp.length);
      // Add space before and after operator for readability
      return beforeOp + ' ' + suggestion + ' ';
    }
    
    // Completing a field name
    if (currentWord) {
      const cleanSuggestion = suggestion.replace(/^["']|["']$/g, '');
      
      // Case-sensitive matching: must start with exact case
      if (cleanSuggestion.startsWith(currentWord)) {
        // Append only the remaining part + SPACE to allow operator suggestions
        const remainder = cleanSuggestion.substring(currentWord.length);
        return currentExpression + remainder + ' ';
      } else {
        // If it doesn't start with current word, replace the whole word + SPACE
        const beforeWord = beforeCursor.substring(0, beforeCursor.length - currentWord.length);
        return beforeWord + suggestion + ' ';
      }
    }
    
    // No current word, just append
    return currentExpression + suggestion;
  };

  /**
   * MAIN TEST: Verify exact TAB/ENTER completion sequence
   * User types partial field → TAB → operator appears → TAB → value appears → TAB
   */
  test('Complete TAB/ENTER flow: field → operator → value', () => {
    let expression = '';
    let suggestions: string[] = [];
    
    // STEP 1: User types partial field name "Src"
    expression = 'Src';
    suggestions = getContextualSuggestions(expression);
    
    // Should suggest fields starting with/containing "Src"
    expect(suggestions).toContain('SrcPort');
    expect(suggestions).toContain('SrcIP');
    
    // STEP 2: User hits TAB/ENTER to complete with "SrcPort"
    expression = insertSuggestion(expression, 'SrcPort');
    
    // Should have inserted "SrcPort" + single space
    expect(expression).toBe('SrcPort ');
    
    // STEP 3: Get suggestions right after field completion (should be empty to close dropdown)
    suggestions = getContextualSuggestions(expression);
    expect(suggestions).toEqual([]);
    
    // STEP 4: User starts typing "=" operator
    expression = 'SrcPort =';
    suggestions = getContextualSuggestions(expression);
    
    // Should suggest operators that start with "=" 
    expect(suggestions).toContain('==');
    expect(suggestions.length).toBeGreaterThan(0);
    
    // STEP 5: User hits TAB/ENTER to complete operator "=="
    expression = insertSuggestion('SrcPort =', '==');
    
    // Should have inserted operator with spaces: "SrcPort  == "
    expect(expression).toMatch(/SrcPort\s+==\s+$/);
    
    // STEP 6: Get value suggestions after operator
    suggestions = getContextualSuggestions(expression);
    
    // Should suggest values for SrcPort (numeric, unquoted)
    expect(suggestions).toContain('80');
    expect(suggestions).toContain('443');
    expect(suggestions).toContain('22');
    
    // STEP 7: User hits TAB/ENTER to complete value "443"
    expression = insertSuggestion(expression, '443');
    
    // Should have inserted value + single space
    expect(expression).toMatch(/443\s+$/);
    
    // STEP 8: Get suggestions after value completion
    suggestions = getContextualSuggestions(expression);
    
    // Should suggest logical operators
    expect(suggestions).toEqual(['&&', '||']);
  });

  test('Field completion adds single space', () => {
    const result = insertSuggestion('Src', 'SrcPort');
    
    // Must end with exactly one space
    expect(result).toBe('SrcPort ');
    expect(result.match(/\s+$/)?.[0].length).toBe(1);
  });

  test('Operator completion adds spaces around operator', () => {
    const result = insertSuggestion('SrcPort =', '==');
    
    // Should have spaces around operator
    expect(result).toMatch(/\s==\s$/);
    
    // Trailing space should be exactly one space
    expect(result.match(/\s+$/)?.[0].length).toBe(1);
  });

  test('Value completion adds single trailing space', () => {
    const result = insertSuggestion('SrcPort == ', '443');
    
    // Must end with exactly one space
    expect(result).toBe('SrcPort == 443 ');
    expect(result.match(/\s+$/)?.[0].length).toBe(1);
  });

  test('String field value completion with quotes', () => {
    let expression = 'Protocol == ';
    let suggestions = getContextualSuggestions(expression);
    
    // Protocol is string type, so suggestions should be quoted
    expect(suggestions).toContain('"TCP"');
    
    // Complete with quoted value
    expression = insertSuggestion(expression, '"TCP"');
    
    // Should have trailing space
    expect(expression).toBe('Protocol == "TCP" ');
    
    // Next suggestions should be logical operators
    suggestions = getContextualSuggestions(expression);
    expect(suggestions).toEqual(['&&', '||']);
  });

  test('Multiple conditions can be chained with TAB completion', () => {
    let expression = '';
    let suggestions: string[] = [];
    
    // Build first condition: SrcPort == 80
    expression = insertSuggestion('Src', 'SrcPort');
    expect(expression).toBe('SrcPort ');
    
    expression = insertSuggestion('SrcPort =', '==');
    expect(expression).toMatch(/==\s+$/);
    
    expression = insertSuggestion(expression, '80');
    expect(expression).toMatch(/80\s+$/);
    
    // Get logical operator suggestions
    suggestions = getContextualSuggestions(expression);
    expect(suggestions).toEqual(['&&', '||']);
    
    // Add logical operator (doesn't add trailing space by itself)
    expression = insertSuggestion(expression, '&&');
    expect(expression).toContain('&&');
    
    // Add space for next field
    expression += ' ';
    
    // Start second condition
    expression += 'Dst';
    suggestions = getContextualSuggestions(expression);
    expect(suggestions).toContain('DstPort');
    
    expression = insertSuggestion(expression, 'DstPort');
    expect(expression).toMatch(/DstPort\s+$/);
  });

  test('Partial field name completion maintains correct spacing', () => {
    // User types "D" and completes to "DstPort"
    const result = insertSuggestion('D', 'DstPort');
    
    // Should be "DstPort " (with single trailing space)
    expect(result).toBe('DstPort ');
  });

  test('Complete field name still adds space when TAB pressed', () => {
    // User types full "SrcPort" and hits TAB
    const result = insertSuggestion('SrcPort', 'SrcPort');
    
    // Should still add the trailing space
    expect(result).toBe('SrcPort ');
  });

  test('After field with space, no suggestions until operator starts', () => {
    // Right after field completion with space - should be empty (close dropdown)
    const expression = 'SrcPort ';
    let suggestions = getContextualSuggestions(expression);
    expect(suggestions).toEqual([]);
    
    // User starts typing "=" (which is not a complete operator, so suggests "==")
    const withPartialOp = expression + '=';
    suggestions = getContextualSuggestions(withPartialOp);
    
    // Should show operators that start with "=" (but not "=" itself since it's not a valid operator)
    expect(suggestions).toContain('==');
    expect(suggestions.length).toBeGreaterThan(0);
  });

  test('After operator with space, value suggestions appear', () => {
    const expression = 'DstPort == ';
    const suggestions = getContextualSuggestions(expression);
    
    // Should show value suggestions for DstPort
    expect(suggestions.length).toBeGreaterThan(0);
    expect(suggestions).toContain('80');
    expect(suggestions).toContain('443');
  });

  test('After value with space, logical operator suggestions appear', () => {
    const expression = 'SrcPort == 443 ';
    const suggestions = getContextualSuggestions(expression);
    
    // Should show only logical operators
    expect(suggestions).toEqual(['&&', '||']);
  });

  test('Case-sensitive field name matching - "PAy" should NOT match "Payload"', () => {
    // Add "Payload" to field suggestions for this test
    const testFieldSuggestions = [...fieldSuggestions, 'Payload'];
    
    const getContextualSuggestionsTest = (inputValue: string): string[] => {
      if (!inputValue) return testFieldSuggestions;

      const cursorPos = inputValue.length;
      const beforeCursor = inputValue.substring(0, cursorPos);
      
      const words = beforeCursor.split(/[\s()&|,]+/);
      const currentWord = words[words.length - 1] || '';
      
      if (currentWord.length >= 1) {
        // Case-sensitive matching: field name must start with exact case
        return testFieldSuggestions.filter(option =>
          option.startsWith(currentWord)
        );
      }

      return testFieldSuggestions;
    };
    
    // Test: "PAy" should NOT match "Payload" (case mismatch)
    let suggestions = getContextualSuggestionsTest('PAy');
    expect(suggestions).not.toContain('Payload');
    expect(suggestions.length).toBe(0);
    
    // Test: "Pay" should match "Payload" (case matches)
    suggestions = getContextualSuggestionsTest('Pay');
    expect(suggestions).toContain('Payload');
    
    // Test: "Src" should match "SrcPort" and "SrcIP" (case matches)
    suggestions = getContextualSuggestionsTest('Src');
    expect(suggestions).toContain('SrcPort');
    expect(suggestions).toContain('SrcIP');
    
    // Test: "src" should NOT match "SrcPort" (case mismatch)
    suggestions = getContextualSuggestionsTest('src');
    expect(suggestions).not.toContain('SrcPort');
    expect(suggestions.length).toBe(0);
  });
});

