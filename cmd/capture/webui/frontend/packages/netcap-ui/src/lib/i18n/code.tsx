import { IntlMessageFormat } from 'intl-messageformat';
import type { ReactNode } from 'react';

const parsed = new Map<string, readonly any[]>();
/** Code/filter examples are opaque English syntax, not translatable prose. */
export function rawCode(pattern: string): string;
export function rawCode(pattern: string, values: Record<string, string | number | bigint | boolean | null | undefined>): string;
export function rawCode(pattern: string, values: Record<string, unknown>): ReactNode;
export function rawCode(pattern: string, values: Record<string, unknown> = {}): ReactNode {
  let ast = parsed.get(pattern);
  if (!ast) { ast = new IntlMessageFormat(pattern, 'en').getAst(); parsed.set(pattern, ast); }
  function render(elements: readonly any[], plural = 0): ReactNode[] {
    return elements.flatMap(element => {
      if (element.type === 0) return [element.value];
      if ([1, 2, 3, 4].includes(element.type)) { const value = values[element.value]; return [value == null ? '' : typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean' ? String(value) : value as ReactNode]; }
      if (element.type === 7) return [String(plural)];
      if (element.type === 8) { const tag = values[element.value]; return typeof tag === 'function' ? [tag(render(element.children))] : render(element.children); }
      if (element.type === 5) return render((element.options[String(values[element.value])] ?? element.options.other).value, plural);
      if (element.type === 6) {
        const value = Number(values[element.value]), offset = element.offset ?? 0;
        const category = new Intl.PluralRules('en', { type: element.pluralType }).select(value - offset);
        return render((element.options[`=${value}`] ?? element.options[category] ?? element.options.other).value, value - offset);
      }
      return [];
    });
  }
  const result = render(ast);
  return result.every(value => typeof value === 'string') ? result.join('') : result;
}
