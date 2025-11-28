/**
 * Syntax highlighting for Regular Expression patterns
 * 
 * Supports standard regex syntax:
 * - Flags ((?i), (?m), etc.)
 * - Groups (capturing and non-capturing)
 * - Character classes [a-z], [^a-z]
 * - Escape sequences \w, \d, \s, etc.
 * - Hex codes \x00
 * - Octal codes \000
 * - Quantifiers *, +, ?, {n,m}
 * - Anchors ^, $
 * - Alternation |
 */

export interface RegexToken {
  type: 'flag' | 'group' | 'charclass' | 'escape' | 'hex' | 'octal' | 'quantifier' | 'backref' | 'anchor' | 'text';
  value: string;
  color: string;
}

/**
 * Tokenize and highlight a regex pattern
 */
export function highlightRegexPattern(pattern: string): RegexToken[] {
  if (!pattern) {
    return [];
  }

  const tokens: RegexToken[] = [];
  let i = 0;

  while (i < pattern.length) {
    let matched = false;

    // Flags like (?i), (?m), (?imsxUXJ)
    if (pattern.substr(i, 2) === '(?') {
      const flagMatch = pattern.substr(i).match(/^\(\?[imsxUXJ]+\)/);
      if (flagMatch) {
        tokens.push({ type: 'flag', value: flagMatch[0], color: '#c586c0' }); // Purple
        i += flagMatch[0].length;
        matched = true;
      }
    }

    // Character classes [...]
    if (!matched && pattern[i] === '[') {
      let j = i + 1;
      let escaped = false;
      while (j < pattern.length) {
        if (escaped) {
          escaped = false;
          j++;
          continue;
        }
        if (pattern[j] === '\\') {
          escaped = true;
          j++;
          continue;
        }
        if (pattern[j] === ']') {
          j++;
          break;
        }
        j++;
      }
      tokens.push({ type: 'charclass', value: pattern.substring(i, j), color: '#4ec9b0' }); // Teal
      i = j;
      matched = true;
    }

    // Hex codes \xAB
    if (!matched && pattern[i] === '\\' && i + 3 < pattern.length && pattern[i + 1] === 'x') {
      const hexMatch = pattern.substr(i).match(/^\\x[0-9A-Fa-f]{2}/);
      if (hexMatch) {
        tokens.push({ type: 'hex', value: hexMatch[0], color: '#ce9178' }); // Orange
        i += hexMatch[0].length;
        matched = true;
      }
    }

    // Octal codes \000
    if (!matched && pattern[i] === '\\' && i + 3 < pattern.length) {
      const octalMatch = pattern.substr(i).match(/^\\[0-7]{3}/);
      if (octalMatch) {
        tokens.push({ type: 'octal', value: octalMatch[0], color: '#ce9178' }); // Orange
        i += octalMatch[0].length;
        matched = true;
      }
    }

    // Escape sequences \w, \W, \d, \D, \s, \S, \n, \r, \t, etc.
    if (!matched && pattern[i] === '\\' && i + 1 < pattern.length) {
      const escapeMatch = pattern.substr(i).match(/^\\[wWdDsSnrtbBAfvP]/);
      if (escapeMatch) {
        tokens.push({ type: 'escape', value: escapeMatch[0], color: '#b5cea8' }); // Light green
        i += escapeMatch[0].length;
        matched = true;
      }
    }

    // Escaped backslash \\
    if (!matched && pattern.substr(i, 2) === '\\\\') {
      tokens.push({ type: 'escape', value: '\\\\', color: '#b5cea8' }); // Light green
      i += 2;
      matched = true;
    }

    // Other escape sequences (generic)
    if (!matched && pattern[i] === '\\' && i + 1 < pattern.length) {
      tokens.push({ type: 'escape', value: pattern.substr(i, 2), color: '#b5cea8' }); // Light green
      i += 2;
      matched = true;
    }

    // Backreferences $1, $2, etc.
    if (!matched && pattern[i] === '$' && i + 1 < pattern.length && /\d/.test(pattern[i + 1])) {
      const backrefMatch = pattern.substr(i).match(/^\$\d+/);
      if (backrefMatch) {
        tokens.push({ type: 'backref', value: backrefMatch[0], color: '#dcdcaa' }); // Yellow
        i += backrefMatch[0].length;
        matched = true;
      }
    }

    // Anchors ^ and $ (only $ if not followed by digit - that's a backref)
    if (!matched && (pattern[i] === '^' || (pattern[i] === '$' && (i + 1 >= pattern.length || !/\d/.test(pattern[i + 1]))))) {
      tokens.push({ type: 'anchor', value: pattern[i], color: '#569cd6' }); // Blue
      i += 1;
      matched = true;
    }

    // Quantifiers and alternation
    if (!matched && /[*+?{}|]/.test(pattern[i])) {
      // Handle {n,m} style quantifiers
      if (pattern[i] === '{') {
        const quantMatch = pattern.substr(i).match(/^\{[0-9,]*\}/);
        if (quantMatch) {
          tokens.push({ type: 'quantifier', value: quantMatch[0], color: '#f44336' }); // Red
          i += quantMatch[0].length;
          matched = true;
        } else {
          tokens.push({ type: 'quantifier', value: pattern[i], color: '#f44336' }); // Red
          i += 1;
          matched = true;
        }
      } else {
        tokens.push({ type: 'quantifier', value: pattern[i], color: '#f44336' }); // Red
        i += 1;
        matched = true;
      }
    }

    // Groups (
    if (!matched && pattern[i] === '(' && !(i + 1 < pattern.length && pattern[i + 1] === '?')) {
      tokens.push({ type: 'group', value: '(', color: '#ffd700' }); // Gold
      i += 1;
      matched = true;
    }

    // Groups )
    if (!matched && pattern[i] === ')') {
      tokens.push({ type: 'group', value: ')', color: '#ffd700' }); // Gold
      i += 1;
      matched = true;
    }

    // Default: plain text
    if (!matched) {
      tokens.push({ type: 'text', value: pattern[i], color: '#d4d4d4' }); // Light gray
      i += 1;
    }
  }

  return tokens;
}

/**
 * Convert regex tokens to HTML string with inline styles
 */
export function regexTokensToHTML(tokens: RegexToken[]): string {
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

