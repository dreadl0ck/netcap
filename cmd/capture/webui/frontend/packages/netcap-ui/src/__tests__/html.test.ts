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
});
