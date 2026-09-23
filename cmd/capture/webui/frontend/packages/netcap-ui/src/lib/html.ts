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
 * HTML-escaping helpers for the few places this UI builds markup as strings.
 *
 * Everything here guards an `innerHTML` or `dangerouslySetInnerHTML` write, and
 * the values passed in are derived from capture files -- record contents, alert
 * payloads, filter expressions typed by the user. React escapes its own JSX, so
 * these functions are the only escaping in the frontend, and they existed as
 * seven separate copies across six files before being collected here.
 *
 * That mattered: `convertTimestamps`, duplicated the same way beside two of
 * them, had already drifted into two behaviours that render the same record
 * differently. A copy of an escaping function drifting is a vulnerability
 * rather than a display bug, which is why these are shared.
 */

/**
 * Escapes the five characters that can change the meaning of markup.
 *
 * Covers attribute contexts as well as text, hence the quotes: the callers here
 * interpolate into `style="..."` as well as between tags.
 */
export function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * As escapeHTML, but renders newlines as <br>.
 *
 * Needed by the contentEditable input, where the value round-trips through
 * innerHTML and a bare "\n" would collapse. Kept as a separate function rather
 * than a flag so a caller cannot inject <br> into an attribute by accident --
 * note the escaping runs first, so a literal "<br>" in the input is still
 * escaped and only real newlines become tags.
 */
export function escapeHTMLPreservingLineBreaks(str: string): string {
  return escapeHTML(str).replace(/\n/g, '<br>');
}

/**
 * Conservative CSS colour validator for values interpolated into a style
 * attribute.
 *
 * Every colour reaching the syntax highlighters today comes from a hardcoded
 * palette or a MUI theme, so this is not currently reachable. It is here
 * because the call site builds `style="color: ${...}"` by hand, and an
 * unvalidated value there is an attribute-injection primitive the moment a
 * theme becomes data-driven -- a colour of `red" onmouseover="alert(1)` would
 * otherwise close the attribute. The chart XSS fixed earlier in this repo was
 * the same assumption: "this string is always ours" holding right up until it
 * did not.
 *
 * Accepts hex, rgb()/rgba()/hsl()/hsla(), and plain CSS keywords such as
 * `inherit` or `currentColor`. Anything else yields `inherit`, which is inert
 * and visually harmless.
 */
export function safeCSSColor(color: string | undefined | null): string {
  if (!color) {
    return 'inherit';
  }

  const value = color.trim();

  // Every shape below is short, so a cap costs nothing and bounds the work
  // before any pattern runs.
  if (value.length > 64) {
    return 'inherit';
  }

  const isHex = /^#[0-9a-fA-F]{3,8}$/.test(value);
  // No `\s*` before the character class: the class already matches whitespace,
  // and the two overlapping made this quadratic on 'rgb(' + '\t'.repeat(n)
  // with no closing paren (CodeQL js/polynomial-redos). Dropping it leaves the
  // accepted language unchanged.
  const isFunctional = /^(?:rgba?|hsla?)\([0-9a-zA-Z.,%\s/+-]+\)$/.test(value);
  const isKeyword = /^[a-zA-Z-]+$/.test(value);

  if (isHex || isFunctional || isKeyword) {
    return value;
  }

  return 'inherit';
}

/** The three characters that can introduce markup in the highlighter output. */
function escapeMarkup(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

/** The \w class, for the word boundaries around true/false/null. */
function isWordChar(c: string | undefined): boolean {
  return (
    c !== undefined &&
    (c === '_' || isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
  );
}

/**
 * Index just past the closing quote of the string literal starting at `start`,
 * or -1 if it is unterminated.
 *
 * One forward pass with no backtracking: a backslash consumes the next
 * character whatever it is. That is deliberately more permissive than JSON --
 * `"\u12"` is an invalid escape that this treats as an escaped 'u' -- because
 * the alternative is a pattern that can fail mid-literal, which is exactly the
 * shape that made the previous implementation quadratic.
 */
function scanStringLiteral(json: string, start: number): number {
  for (let i = start + 1; i < json.length; i++) {
    const c = json[i];

    if (c === '\\') {
      i++;
      continue;
    }

    if (c === '"') {
      return i + 1;
    }
  }

  return -1;
}

/**
 * Index just past the number starting at `start`, or -1 if there is none.
 *
 * Mirrors -?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?, returning to the pre-exponent mark
 * when an 'e' is not followed by digits.
 */
function scanNumber(json: string, start: number): number {
  let i = start;

  if (json[i] === '-') {
    i++;
  }

  if (!isDigit(json[i])) {
    return -1;
  }

  while (isDigit(json[i])) {
    i++;
  }

  if (json[i] === '.') {
    i++;
    while (isDigit(json[i])) {
      i++;
    }
  }

  const beforeExponent = i;

  if (json[i] === 'e' || json[i] === 'E') {
    i++;

    if (json[i] === '+' || json[i] === '-') {
      i++;
    }

    if (!isDigit(json[i])) {
      return beforeExponent;
    }

    while (isDigit(json[i])) {
      i++;
    }
  }

  return i;
}

const KEYWORDS: ReadonlyArray<readonly [string, string]> = [
  ['true', 'boolean'],
  ['false', 'boolean'],
  ['null', 'null'],
];

/**
 * Renders a JSON string as HTML with per-token <span> classes.
 *
 * The security property is that EVERY character of the output passes through
 * escapeMarkup, so the spans this function emits are the only tags in the
 * result and any '<' from the data is inert. Output goes to
 * dangerouslySetInnerHTML on the alert, record and audit detail views, where
 * the JSON is a decoded audit record -- attacker-influenced by definition,
 * since it is parsed off the wire.
 *
 * This is a hand-written scanner rather than one tokenising regex because the
 * regex was unanchored: on '"' followed by many '\"' with no terminator the
 * engine restarted at every quote and rescanned the whole run, O(n^2) on data
 * that arrives off the wire (CodeQL js/polynomial-redos). A single left-to-
 * right pass with no backtracking is linear by construction.
 */
export function syntaxHighlightJSON(json: string): string {
  let out = '';
  let plainStart = 0;
  let i = 0;

  // A failed string scan reaches the end of the input, so every later quote
  // fails identically: it was either skipped as an escaped character by the
  // scan that failed, or the scan would have returned at it. Recording the
  // failure is what keeps this linear -- retrying at each quote is precisely
  // the rescanning the previous regex was flagged for.
  let stringScanFailed = false;

  while (i < json.length) {
    const c = json[i];
    let end = -1;
    let cls = '';

    if (c === '"' && !stringScanFailed) {
      const close = scanStringLiteral(json, i);

      if (close === -1) {
        stringScanFailed = true;
      } else {
        // A literal followed by a colon is an object key, and the span covers
        // the colon as the previous pattern's "(\s*:)? group did.
        let k = close;
        while (k < json.length && /\s/.test(json[k])) {
          k++;
        }

        if (json[k] === ':') {
          cls = 'key';
          end = k + 1;
        } else {
          cls = 'string';
          end = close;
        }
      }
    } else if (isDigit(c) || (c === '-' && isDigit(json[i + 1]))) {
      cls = 'number';
      end = scanNumber(json, i);
    } else if (!isWordChar(json[i - 1])) {
      for (const [word, kind] of KEYWORDS) {
        if (json.startsWith(word, i) && !isWordChar(json[i + word.length])) {
          cls = kind;
          end = i + word.length;
          break;
        }
      }
    }

    if (end <= i) {
      i++;
      continue;
    }

    out += escapeMarkup(json.slice(plainStart, i));
    out += '<span class="json-' + cls + '">' + escapeMarkup(json.slice(i, end)) + '</span>';

    i = end;
    plainStart = i;
  }

  return out + escapeMarkup(json.slice(plainStart));
}
