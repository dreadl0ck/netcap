/** Pretty-print without rewriting numeric lexemes, escapes, keys or evidence text. */
export function formatEvidenceJSON(raw: string): string {
  try { JSON.parse(raw); } catch { return raw; }
  const tokens = raw.match(/"(?:\\[\s\S]|[^"\\])*"|[^\s{}\[\],:]+|[{}\[\],:]/g) ?? [];
  const output: string[] = [];
  let depth = 0;
  const newline = () => output.push('\n', '  '.repeat(depth));
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (token === '{' || token === '[') {
      output.push(token);
      if (tokens[index + 1] === (token === '{' ? '}' : ']')) output.push(tokens[++index]);
      else { depth++; newline(); }
    } else if (token === '}' || token === ']') {
      depth--; newline(); output.push(token);
    } else if (token === ',') { output.push(token); newline(); }
    else if (token === ':') output.push(': ');
    else output.push(token);
  }
  return output.join('');
}
