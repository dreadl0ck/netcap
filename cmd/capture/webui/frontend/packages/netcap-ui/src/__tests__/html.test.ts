/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { describe, it, expect } from 'vitest';

import {
  escapeHTML,
  escapeHTMLPreservingLineBreaks,
  safeCSSColor,
  syntaxHighlightJSON,
} from '../lib/html';

const PAYLOAD = `</script><img src=x onerror=alert('vulnerable')>`;

describe('escapeHTML', () => {
  it('escapes the five markup-significant characters', () => {
    expect(escapeHTML(`<a href="x">&'`)).toBe('&lt;a href=&quot;x&quot;&gt;&amp;&#039;');
  });

  it('escapes ampersands before the others, so entities are not double-built', () => {
    // If '<' were replaced first, its '&lt;' would then have its '&' escaped
    // again and render literally as "&lt;".
    expect(escapeHTML('<')).toBe('&lt;');
    expect(escapeHTML('&lt;')).toBe('&amp;lt;');
  });

  it('neutralises a script breakout', () => {
    const out = escapeHTML(PAYLOAD);
    expect(out).not.toContain('<');
    expect(out).not.toContain('>');
  });
});

describe('escapeHTMLPreservingLineBreaks', () => {
  it('turns real newlines into <br>', () => {
    expect(escapeHTMLPreservingLineBreaks('a\nb')).toBe('a<br>b');
  });

  it('does not let a literal <br> in the input become a tag', () => {
    // Escaping runs before the newline substitution, so only real newlines
    // become markup.
    expect(escapeHTMLPreservingLineBreaks('<br>')).toBe('&lt;br&gt;');
  });

  it('still escapes a payload', () => {
    expect(escapeHTMLPreservingLineBreaks(PAYLOAD)).not.toContain('<img');
  });
});

describe('safeCSSColor', () => {
  it('passes through the shapes the highlighters actually use', () => {
    for (const c of ['#fff', '#00ff41', '#00ff4180', 'inherit', 'currentColor', 'red']) {
      expect(safeCSSColor(c)).toBe(c);
    }

    expect(safeCSSColor('rgb(0, 255, 65)')).toBe('rgb(0, 255, 65)');
    expect(safeCSSColor('rgba(0,255,65,0.5)')).toBe('rgba(0,255,65,0.5)');
    expect(safeCSSColor('hsl(140 100% 50%)')).toBe('hsl(140 100% 50%)');
  });

  it('rejects an attribute breakout', () => {
    // The reason this function exists: the value is interpolated into
    // style="color: ${...}", where escaping the token text is no defence.
    expect(safeCSSColor('red" onmouseover="alert(1)')).toBe('inherit');
    expect(safeCSSColor('red;background:url(javascript:alert(1))')).toBe('inherit');
    expect(safeCSSColor('</style><script>alert(1)</script>')).toBe('inherit');
  });

  it('falls back to inherit for empty input', () => {
    expect(safeCSSColor('')).toBe('inherit');
    expect(safeCSSColor(undefined)).toBe('inherit');
    expect(safeCSSColor(null)).toBe('inherit');
  });

  it('rejects an over-long value without scanning it', () => {
    expect(safeCSSColor('#' + 'a'.repeat(100))).toBe('inherit');
  });

  // The functional-colour pattern had a \s* next to a character class that also
  // matched whitespace, so this input cost O(n^2). Two defences now stand in
  // the way -- the length cap above and the pattern itself -- and this asserts
  // only the observable result, so it fails if both are removed rather than
  // proving either one. Quadratic here is ~10^10 steps, so the bound separates
  // the behaviours by orders of magnitude rather than by a flakeable margin.
  it('does not backtrack on a long unterminated rgb( prefix', () => {
    const started = Date.now();
    expect(safeCSSColor('rgb(' + '\t'.repeat(100_000))).toBe('inherit');
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe('syntaxHighlightJSON', () => {
  it('adds span classes for each token type', () => {
    const out = syntaxHighlightJSON('{"k": "v", "n": 1, "b": true, "z": null}');
    expect(out).toContain('class="json-key"');
    expect(out).toContain('class="json-string"');
    expect(out).toContain('class="json-number"');
    expect(out).toContain('class="json-boolean"');
    expect(out).toContain('class="json-null"');
  });

  // This is the security property, and its ordering is what makes it work:
  // escaping must happen BEFORE tokenising, or the spans added here would
  // themselves be escaped while the payload stayed live.
  it('escapes markup in values before adding its own spans', () => {
    const out = syntaxHighlightJSON(JSON.stringify({ ua: PAYLOAD }));

    expect(out).not.toContain('<img');
    expect(out).not.toContain('</script>');
    expect(out).toContain('&lt;');

    // Its own spans survive as real tags.
    expect(out).toContain('<span class="json-');
  });

  it('escapes a payload that tries to forge a span', () => {
    const out = syntaxHighlightJSON(JSON.stringify({ x: '<span class="json-key">' }));
    expect(out).toContain('&lt;span');
  });

  it('leaves the only unescaped angle brackets to be its own markup', () => {
    const out = syntaxHighlightJSON(JSON.stringify({ ua: PAYLOAD }));
    // Every '<' in the output must open one of our spans.
    const opens = out.match(/</g) ?? [];
    const spanOpens = out.match(/<span class="json-|<\/span>/g) ?? [];
    expect(opens.length).toBe(spanOpens.length);
  });

  it('emits the exact spans the regex implementation did', () => {
    expect(syntaxHighlightJSON('{"k": "v", "n": -1.5e+3, "b": false, "z": null}')).toBe(
      '{<span class="json-key">"k":</span> <span class="json-string">"v"</span>, ' +
        '<span class="json-key">"n":</span> <span class="json-number">-1.5e+3</span>, ' +
        '<span class="json-key">"b":</span> <span class="json-boolean">false</span>, ' +
        '<span class="json-key">"z":</span> <span class="json-null">null</span>}',
    );
  });

  it('spans a key through its colon and a value string without one', () => {
    const out = syntaxHighlightJSON('{\n  "k" : "v"\n}');
    expect(out).toContain('<span class="json-key">"k" :</span>');
    expect(out).toContain('<span class="json-string">"v"</span>');
  });

  it('treats an unterminated string as text, not a token', () => {
    const out = syntaxHighlightJSON('{"k": "unterminated');
    expect(out).toContain('<span class="json-key">"k":</span>');
    expect(out).not.toContain('json-string');
    expect(out.endsWith('"unterminated')).toBe(true);
  });

  it('escapes markup inside a token that never terminates', () => {
    expect(syntaxHighlightJSON('"<img src=x>')).toBe('"&lt;img src=x&gt;');
  });

  // The previous pattern was unanchored, so on this input the engine restarted
  // at every quote and rescanned the run behind it: O(n^2), on JSON parsed off
  // the wire (CodeQL js/polynomial-redos).
  it('does not rescan a long run of escaped quotes', () => {
    const started = Date.now();
    const out = syntaxHighlightJSON('"' + '\\"'.repeat(100_000));
    expect(Date.now() - started).toBeLessThan(1000);
    expect(out).not.toContain('<span');
  });
});
