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

  const isHex = /^#[0-9a-fA-F]{3,8}$/.test(value);
  const isFunctional = /^(rgb|rgba|hsl|hsla)\(\s*[0-9a-zA-Z.,%\s/+-]+\)$/.test(value);
  const isKeyword = /^[a-zA-Z-]+$/.test(value);

  if (isHex || isFunctional || isKeyword) {
    return value;
  }

  return 'inherit';
}

/**
 * Renders a JSON string as HTML with per-token <span> classes.
 *
 * The escaping on the first line is the whole security property, and its
 * position is load-bearing: it must run BEFORE the tokenising replace, so that
 * the spans this function adds are the only tags in the output and any '<' from
 * the data is already inert. Escaping afterwards would neutralise the spans and
 * leave the payload live.
 *
 * Output goes to dangerouslySetInnerHTML on the alert, record and audit detail
 * views, where the JSON is a decoded audit record -- attacker-influenced by
 * definition, since it is parsed off the wire.
 */
export function syntaxHighlightJSON(json: string): string {
  const escaped = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  return escaped.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    (match) => {
      let cls = 'number';

      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'key' : 'string';
      } else if (/true|false/.test(match)) {
        cls = 'boolean';
      } else if (/null/.test(match)) {
        cls = 'null';
      }

      return '<span class="json-' + cls + '">' + match + '</span>';
    },
  );
}
